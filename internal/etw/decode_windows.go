//go:build windows

package etw

import (
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"
)

// Event ids on Microsoft-Windows-Kernel-File, confirmed against a tracerpt dump
// of a real capture rather than taken from documentation. Every layout below is
// length-checked before a field is touched: an unexpected version must fail
// closed rather than be parsed by positional guesswork.
const (
	evNameCreate   = 10
	evNameDelete   = 11
	evCreate       = 12
	evCleanup      = 13
	evClose        = 14
	evRead         = 15
	evOperationEnd = 24
)

// Classic FileIo event types. FileRundown is the one that matters: it is emitted
// for files that were already open when the rundown was requested.
const (
	fileIoNameType    = 0
	fileIoFileCreate  = 32
	fileIoFileDelete  = 35
	fileIoFileRundown = 36
)

var errShort = errors.New("event payload shorter than its declared layout")

// readEvent is Read (15). It carries no path: the name has to come from a
// FileObject or FileKey seen on another event, and the outcome from matching
// Irp against OperationEnd.
type readEvent struct {
	ByteOffset      uint64
	Irp             uint64
	FileObject      uint64
	FileKey         uint64
	IssuingThreadID uint32
	IOSize          uint32
}

// readFixedLen is the whole fixed payload of Read v1 on amd64: ByteOffset, Irp,
// FileObject, FileKey (8 each), then IssuingThreadId, IOSize, IOFlags,
// ExtraFlags (4 each). Requiring the complete prefix rather than only the part
// this reads is what "fail closed on an unknown version" actually means —
// accepting 40 would silently parse a different, shorter schema as this one.
const readFixedLen = 48

func decodeRead(b []byte) (readEvent, error) {
	var r readEvent
	if len(b) < readFixedLen {
		return r, errShort
	}
	r.ByteOffset = binary.LittleEndian.Uint64(b[0:])
	r.Irp = binary.LittleEndian.Uint64(b[8:])
	r.FileObject = binary.LittleEndian.Uint64(b[16:])
	r.FileKey = binary.LittleEndian.Uint64(b[24:])
	r.IssuingThreadID = binary.LittleEndian.Uint32(b[32:])
	r.IOSize = binary.LittleEndian.Uint32(b[36:])
	return r, nil
}

// nameEvent is NameCreate (10) and NameDelete (11): FileKey then the NT path.
type nameEvent struct {
	FileKey uint64
	Name    string
}

func decodeName(b []byte) (nameEvent, error) {
	var n nameEvent
	if len(b) < 8 {
		return n, errShort
	}
	n.FileKey = binary.LittleEndian.Uint64(b[0:])
	n.Name = utf16FromBytes(b[8:])
	return n, nil
}

// createEvent is Create (12): the other half of name resolution, keyed by
// FileObject rather than FileKey.
type createEvent struct {
	Irp        uint64
	FileObject uint64
	Name       string
}

func decodeCreate(b []byte) (createEvent, error) {
	var c createEvent
	if len(b) < 32 {
		return c, errShort
	}
	c.Irp = binary.LittleEndian.Uint64(b[0:])
	c.FileObject = binary.LittleEndian.Uint64(b[8:])
	c.Name = utf16FromBytes(b[32:])
	return c, nil
}

// opEndEvent is OperationEnd (24): whether the read actually succeeded.
type opEndEvent struct {
	Irp uint64
	// ExtraInformation is the bytes actually transferred. The Read event carries
	// only the size that was *asked* for, so reporting that as the read would
	// overstate a short read and invent one for a request that returned nothing.
	ExtraInformation uint64
	Status           uint32
}

func decodeOpEnd(b []byte) (opEndEvent, error) {
	var o opEndEvent
	if len(b) < 20 {
		return o, errShort
	}
	o.Irp = binary.LittleEndian.Uint64(b[0:])
	o.ExtraInformation = binary.LittleEndian.Uint64(b[8:])
	o.Status = binary.LittleEndian.Uint32(b[16:])
	return o, nil
}

// closeEvent is Cleanup (13) and Close (14): when a name mapping may be retired.
// Layout is Irp, FileObject, FileKey, IssuingThreadId.
type closeEvent struct {
	FileObject uint64
	FileKey    uint64
}

func decodeClose(b []byte) (closeEvent, error) {
	var c closeEvent
	if len(b) < 24 {
		return c, errShort
	}
	c.FileObject = binary.LittleEndian.Uint64(b[8:])
	c.FileKey = binary.LittleEndian.Uint64(b[16:])
	return c, nil
}

// decodeFileIoName decodes the classic FileIo Name/FileCreate/FileDelete/
// FileRundown payload: a FileObject pointer followed by the file's name. That
// pointer is the value a manifest Read carries as its FileKey — the join was
// verified by an exact match on all forty reads of a handle opened before the
// session started.
func decodeFileIoName(b []byte) (uint64, string, error) {
	if len(b) < 8 {
		return 0, "", errShort
	}
	return binary.LittleEndian.Uint64(b[0:]), utf16FromBytes(b[8:]), nil
}

// utf16FromBytes reads a null-terminated UTF-16 string out of an event payload,
// stopping at the end of the buffer if the provider did not terminate it.
func utf16FromBytes(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		c := binary.LittleEndian.Uint16(b[i*2:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return syscall.UTF16ToString(u)
}

// payload copies the provider's bytes out while the record is still live. ETW
// owns that memory only for the duration of the callback, so nothing may retain
// it: every decode above works on this Go-owned copy.
func payload(rec *EVENT_RECORD) []byte {
	if rec.UserData == nil || rec.UserDataLength == 0 {
		return nil
	}
	src := unsafe.Slice((*byte)(rec.UserData), int(rec.UserDataLength))
	out := make([]byte, len(src))
	copy(out, src)
	return out
}
