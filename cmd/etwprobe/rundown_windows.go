//go:build windows

package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// The manifest provider's own EVENT_CONTROL_CODE_CAPTURE_STATE documents no
// promise to enumerate every live file object, and measured here it did not name
// a file that was already open. The documented mechanism that does is the
// directed system rundown: run the session as a SystemTraceProvider logger with
// disk file I/O enabled, then ask SystemTraceControlGuid to capture state with a
// filter naming this session's own trace handle. That emits classic FileIo
// FileRundown events, each carrying FileObject and the file's name.

const (
	EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000

	EVENT_TRACE_FLAG_DISK_IO      = 0x00000100
	EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200
	// The two that were missing. DISK_FILE_IO alone yields file *names*; the
	// file-I/O operations themselves — and their completions — need these, and a
	// rundown of open files plausibly needs the operation class enabled too.
	EVENT_TRACE_FLAG_FILE_IO      = 0x02000000
	EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000

	// EVENT_FILTER_TYPE_TRACEHANDLE names the session the rundown should be
	// directed at, which is what makes this "capture state for me" rather than a
	// broadcast to every listener.
	EVENT_FILTER_TYPE_TRACEHANDLE = 0x80000002

	// Classic FileIo event types. FileRundown is the one that matters: it is
	// emitted for files that were already open when the rundown was requested.
	fileIoNameType    = 0
	fileIoFileCreate  = 32
	fileIoFileDelete  = 35
	fileIoFileRundown = 36
	// Classic read/write and completion. Consuming the read side from the same
	// provider as the names removes the cross-provider join entirely — the
	// documented equality is classic ReadWrite.FileKey == classic Name.FileObject.
	fileIoRead         = 67
	fileIoWrite        = 68
	fileIoOperationEnd = 76
)

// SystemTraceControlGuid {9E814AAD-3204-11D2-9A82-006008A86939}
var systemTraceControlGUID = GUID{0x9E814AAD, 0x3204, 0x11D2, [8]byte{0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39}}

// FileIoGuid {90CBDC39-4A3E-11D1-84F4-0000F80464E3} — the classic MOF provider
// the rundown events arrive under, which is a different identity from the
// manifest Microsoft-Windows-Kernel-File. Dispatch has to key on the provider,
// not on the event number, because the two numbering spaces overlap.
var fileIoGUID = GUID{0x90CBDC39, 0x4A3E, 0x11D1, [8]byte{0x84, 0xF4, 0x00, 0x00, 0xF8, 0x04, 0x64, 0xE3}}

// probeSessionGUID identifies this session's own logger. A multiplexed system
// logger needs a Wnode.Guid that is not SystemTraceControlGuid, or it competes
// for the single legacy NT Kernel Logger instead of getting its own.
var probeSessionGUID = GUID{0x5A2E1F00, 0x9B41, 0x4C7D, [8]byte{0xA3, 0x11, 0x52, 0x65, 0x61, 0x64, 0x57, 0x31}}

type EVENT_FILTER_DESCRIPTOR struct {
	Ptr  uint64
	Size uint32
	Type uint32
}

func (g GUID) equals(o GUID) bool {
	return g.Data1 == o.Data1 && g.Data2 == o.Data2 && g.Data3 == o.Data3 && g.Data4 == o.Data4
}

// requestSystemRundown asks for the directed rundown against this session. The
// timeout is deliberately non-zero so the provider callback has completed when
// this returns; that is not yet proof the events have been consumed, which is
// what the flush below is for.
func (s *session) requestSystemRundown() error {
	if s.handle == 0 || s.trace == 0 {
		return fmt.Errorf("rundown requested without both a live session and an attached consumer")
	}
	// Which handle EVENT_FILTER_TYPE_TRACEHANDLE wants is settled by measurement
	// here, not by argument. The documented reading is the session handle from
	// StartTrace; a review made that point and it is a reasonable reading. But on
	// this host the session handle produces **zero** rundown events while the
	// OpenTrace processing handle produces ~140,000, and a rundown that emits
	// nothing cannot be the correct configuration whatever the prose says.
	//
	// Both are selectable so the run reports which one works rather than either
	// of us asserting it. The handle must stay alive and unmoved for the call:
	// the filter holds its address, not a copy.
	handle := s.trace
	if useSessionHandle {
		handle = s.handle
	}
	desc := EVENT_FILTER_DESCRIPTOR{
		Ptr:  uint64(uintptr(unsafe.Pointer(&handle))),
		Size: uint32(unsafe.Sizeof(handle)),
		Type: EVENT_FILTER_TYPE_TRACEHANDLE,
	}
	params := ENABLE_TRACE_PARAMETERS{
		Version:          2,
		EnableFilterDesc: unsafe.Pointer(&desc),
		FilterDescCount:  1,
	}
	r, _, _ := procEnableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&systemTraceControlGUID)),
		EVENT_CONTROL_CODE_CAPTURE_STATE,
		0, // level: the SDK-directed request takes zero level and keywords
		0, 0,
		10_000, // ms; synchronous so the provider has finished when this returns
		uintptr(unsafe.Pointer(&params)),
	)
	runtime.KeepAlive(handle)
	runtime.KeepAlive(desc)
	runtime.KeepAlive(params)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("EnableTraceEx2(system rundown): %w", syscall.Errno(r))
	}
	return nil
}

// flush pushes whatever is sitting in the session's buffers to the consumer, so
// a rundown can be waited on rather than guessed at.
func (s *session) flush() error {
	buf, _ := propertiesBuffer(sessionName, true)
	writeLoggerName(buf, uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})), sessionName)
	r, _, _ := procControlTraceW.Call(
		uintptr(s.handle), 0,
		uintptr(unsafe.Pointer(&buf[0])),
		EVENT_TRACE_CONTROL_FLUSH,
	)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("ControlTrace(flush): %w", syscall.Errno(r))
	}
	return nil
}

// decodeFileIoName decodes the classic FileIo Name/FileCreate/FileDelete/
// FileRundown payload: a FileObject pointer followed by the file's name. On
// amd64 the pointer is eight bytes; a 32-bit trace would be four, which is why
// the caller checks the pointer-size flag rather than assuming.
func decodeFileIoName(b []byte) (uint64, string, error) {
	if len(b) < 8 {
		return 0, "", errShort
	}
	obj := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return obj, utf16FromBytes(b[8:]), nil
}
