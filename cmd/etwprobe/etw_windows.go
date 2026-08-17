//go:build windows

// Package main is a disposable qualification probe for the
// Microsoft-Windows-Kernel-File ETW provider. It exists to answer whether that
// provider can replace the audit-rule mechanism, and it is deleted once it has.
// Nothing here is production code and nothing in the app imports it.
package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")

	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procQueryDosDeviceW  = kernel32.NewProc("QueryDosDeviceW")
	procGetLogicalDrives = kernel32.NewProc("GetLogicalDrives")
)

const (
	WNODE_FLAG_TRACED_GUID     = 0x00020000
	EVENT_TRACE_REAL_TIME_MODE = 0x00000100

	PROCESS_TRACE_MODE_REAL_TIME     = 0x00000100
	PROCESS_TRACE_MODE_EVENT_RECORD  = 0x10000000
	PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000

	EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
	EVENT_CONTROL_CODE_ENABLE_PROVIDER  = 1
	// CAPTURE_STATE is the rundown: it asks the provider to describe what it
	// already knows about. For this provider that is the names of files that were
	// already open when the session started, without which their reads can never
	// be resolved to a path.
	EVENT_CONTROL_CODE_CAPTURE_STATE = 2

	TRACE_LEVEL_VERBOSE = 5

	ERROR_SUCCESS                = 0
	ERROR_ALREADY_EXISTS         = 183
	ERROR_WMI_INSTANCE_NOT_FOUND = 4201
	ERROR_CTX_CLOSE_PENDING      = 7007

	EVENT_TRACE_CONTROL_STOP  = 1
	EVENT_TRACE_CONTROL_QUERY = 0
	EVENT_TRACE_CONTROL_FLUSH = 3

	INVALID_PROCESSTRACE_HANDLE = ^uint64(0)
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// kernelFileProvider is {EDD08927-9CC4-4E65-B970-C2560FB5C289}.
var kernelFileProvider = GUID{0xEDD08927, 0x9CC4, 0x4E65, [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}}

type WNODE_HEADER struct {
	BufferSize        uint32
	ProviderId        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              GUID
	ClientContext     uint32
	Flags             uint32
}

type EVENT_TRACE_PROPERTIES struct {
	Wnode               WNODE_HEADER
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type EVENT_DESCRIPTOR struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type EVENT_HEADER struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      GUID
	EventDescriptor EVENT_DESCRIPTOR
	KernelTime      uint32
	UserTime        uint32
	ActivityId      GUID
}

type ETW_BUFFER_CONTEXT struct {
	ProcessorIndex uint16
	LoggerId       uint16
}

// EVENT_RECORD's three native pointers are declared as unsafe.Pointer rather
// than uintptr on purpose. Storing them as uintptr and converting back is the
// pattern `go vet` flags, and this project may not suppress that check.
type EVENT_RECORD struct {
	EventHeader       EVENT_HEADER
	BufferContext     ETW_BUFFER_CONTEXT
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      unsafe.Pointer
	UserData          unsafe.Pointer
	UserContext       unsafe.Pointer
}

type SYSTEMTIME struct {
	Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds uint16
}

type TIME_ZONE_INFORMATION struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate SYSTEMTIME
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate SYSTEMTIME
	DaylightBias int32
}

type EVENT_TRACE_HEADER struct {
	Size           uint16
	FieldTypeFlags uint16
	Version        uint32
	ThreadId       uint32
	ProcessId      uint32
	TimeStamp      int64
	Guid           GUID
	ClientContext  uint32
	Flags          uint32
}

type EVENT_TRACE struct {
	Header           EVENT_TRACE_HEADER
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       GUID
	MofData          unsafe.Pointer
	MofLength        uint32
	ClientContext    uint32
}

type TRACE_LOGFILE_HEADER struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGuid    GUID
	LoggerName         *uint16
	LogFileName        *uint16
	TimeZone           TIME_ZONE_INFORMATION
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

type EVENT_TRACE_LOGFILEW struct {
	LogFileName      *uint16
	LoggerName       *uint16
	CurrentTime      int64
	BuffersRead      uint32
	ProcessTraceMode uint32
	CurrentEvent     EVENT_TRACE
	LogfileHeader    TRACE_LOGFILE_HEADER
	BufferCallback   uintptr
	BufferSize       uint32
	Filled           uint32
	EventsLost       uint32
	EventCallback    uintptr
	IsKernelTrace    uint32
	Context          unsafe.Pointer
}

type ENABLE_TRACE_PARAMETERS struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceId         GUID
	EnableFilterDesc unsafe.Pointer
	FilterDescCount  uint32
}

// checkLayout fails loudly rather than parsing garbage. Every one of these is a
// structure Windows writes into, so a wrong offset here is silent corruption,
// not a compile error.
func checkLayout() error {
	type want struct {
		name string
		got  uintptr
		want uintptr
	}
	for _, c := range []want{
		{"GUID", unsafe.Sizeof(GUID{}), 16},
		{"WNODE_HEADER", unsafe.Sizeof(WNODE_HEADER{}), 48},
		{"EVENT_TRACE_PROPERTIES", unsafe.Sizeof(EVENT_TRACE_PROPERTIES{}), 120},
		{"EVENT_DESCRIPTOR", unsafe.Sizeof(EVENT_DESCRIPTOR{}), 16},
		{"EVENT_HEADER", unsafe.Sizeof(EVENT_HEADER{}), 80},
		// 80 header + 4 buffer context + 2 + 2, then three 8-byte pointers.
		{"EVENT_RECORD", unsafe.Sizeof(EVENT_RECORD{}), 112},
		{"TIME_ZONE_INFORMATION", unsafe.Sizeof(TIME_ZONE_INFORMATION{}), 172},
		{"EVENT_TRACE_HEADER", unsafe.Sizeof(EVENT_TRACE_HEADER{}), 48},
		{"EVENT_TRACE", unsafe.Sizeof(EVENT_TRACE{}), 88},
		{"EVENT_RECORD.UserData offset", unsafe.Offsetof(EVENT_RECORD{}.UserData), 96},
		// EVENT_TRACE_LOGFILEW is the one ProcessTrace writes into, so a wrong
		// offset here means Windows scribbles through a displaced callback or
		// context pointer. It was the largest unasserted structure and is the one
		// a review specifically asked to see checked.
		{"TRACE_LOGFILE_HEADER", unsafe.Sizeof(TRACE_LOGFILE_HEADER{}), 280},
		{"EVENT_TRACE_LOGFILEW", unsafe.Sizeof(EVENT_TRACE_LOGFILEW{}), 448},
		{"LOGFILEW.CurrentEvent offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.CurrentEvent), 32},
		{"LOGFILEW.LogfileHeader offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.LogfileHeader), 120},
		{"LOGFILEW.BufferCallback offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.BufferCallback), 400},
		{"LOGFILEW.EventCallback offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.EventCallback), 424},
		{"LOGFILEW.Context offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.Context), 440},
		{"EVENT_FILTER_DESCRIPTOR", unsafe.Sizeof(EVENT_FILTER_DESCRIPTOR{}), 16},
		// 12 bytes of ULONGs, then a 4-aligned GUID at 12, then the pointer pads
		// out to 32, then a trailing ULONG rounded to the struct's 8 alignment.
		{"ENABLE_TRACE_PARAMETERS", unsafe.Sizeof(ENABLE_TRACE_PARAMETERS{}), 48},
	} {
		if c.got != c.want {
			return fmt.Errorf("%s is %d bytes, want %d — the ABI is wrong and every field read would be garbage", c.name, c.got, c.want)
		}
	}
	return nil
}

// sessionName is deliberately distinctive: an orphaned session has to be
// recognisable as this probe's and nothing else's.
const sessionName = "ReadWatchETWProbe"

type session struct {
	handle uint64 // TRACEHANDLE from StartTraceW
	trace  uint64 // TRACEHANDLE from OpenTraceW
	props  []byte
	// ready closes once OpenTraceW has succeeded. A rundown asked for before
	// that is delivered to nobody, and a fixed sleep is not proof of anything.
	ready chan struct{}
}

// waitConsumerReady blocks until the consumer is attached, or gives up and says
// so rather than proceeding on an assumption.
func (s *session) waitConsumerReady(timeout time.Duration) error {
	select {
	case <-s.ready:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("the consumer did not attach within %s", timeout)
	}
}

// propertiesBuffer lays out EVENT_TRACE_PROPERTIES followed by the logger name,
// which is how Windows expects the name to be passed.
func propertiesBuffer(name string, realtime bool) ([]byte, *EVENT_TRACE_PROPERTIES) {
	nameUTF16 := syscall.StringToUTF16(name)
	structSize := int(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{}))
	// Room for both the logger name and a log-file name slot Windows may write.
	total := structSize + (len(nameUTF16)+260)*2
	buf := make([]byte, total)
	p := (*EVENT_TRACE_PROPERTIES)(unsafe.Pointer(&buf[0]))
	p.Wnode.BufferSize = uint32(total)
	p.Wnode.Flags = WNODE_FLAG_TRACED_GUID
	p.Wnode.ClientContext = 1 // QPC
	// A system logger needs its own identity here. Leaving this zero, or setting
	// it to SystemTraceControlGuid, asks for the single legacy NT Kernel Logger
	// instead of a private multiplexed one.
	p.Wnode.Guid = probeSessionGUID
	p.LoggerNameOffset = uint32(structSize)
	p.LogFileNameOffset = 0
	// 64 KB rather than 1 MB: Microsoft's guidance is that most sessions want
	// 64 KB or less, and the earlier 1 MB x 64-256 envelope reserved up to 256 MB
	// for what is meant to be a lightweight consumer.
	p.BufferSize = 64
	p.MinimumBuffers = 64
	p.MaximumBuffers = 256
	p.FlushTimer = 1
	if realtime {
		p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE
	}
	// Disk file I/O is what carries the classic FileRundown; Windows requires
	// DISK_IO to be enabled alongside it.
	p.EnableFlags = EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_FILE_IO |
		EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT
	return buf, p
}

func writeLoggerName(buf []byte, offset uint32, name string) {
	n := syscall.StringToUTF16(name)
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[offset])), len(n))
	copy(dst, n)
}

// stopStaleSession clears an orphan from a previous run. It names the session
// explicitly, so it can never stop a session belonging to anything else.
func stopStaleSession() {
	buf, _ := propertiesBuffer(sessionName, true)
	writeLoggerName(buf, uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})), sessionName)
	procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(sessionName))),
		uintptr(unsafe.Pointer(&buf[0])),
		EVENT_TRACE_CONTROL_STOP,
	)
}

func startSession() (*session, error) {
	if err := checkLayout(); err != nil {
		return nil, err
	}
	stopStaleSession()

	buf, props := propertiesBuffer(sessionName, true)
	writeLoggerName(buf, props.LoggerNameOffset, sessionName)

	var handle uint64
	r, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(sessionName))),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r != ERROR_SUCCESS {
		if r == ERROR_ALREADY_EXISTS {
			return nil, fmt.Errorf("StartTrace: a session named %s already exists", sessionName)
		}
		return nil, fmt.Errorf("StartTrace: %w", syscall.Errno(r))
	}
	s := &session{handle: handle, props: buf, ready: make(chan struct{})}

	params := ENABLE_TRACE_PARAMETERS{Version: 2}
	r, _, _ = procEnableTraceEx2.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&kernelFileProvider)),
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE,
		uintptr(keywordsAny), 0, 0,
		uintptr(unsafe.Pointer(&params)),
	)
	if r != ERROR_SUCCESS {
		s.Stop()
		return nil, fmt.Errorf("EnableTraceEx2(enable): %w", syscall.Errno(r))
	}
	return s, nil
}

// captureState triggers the filename rundown. Without it, a read on a handle
// that was already open when the session started carries a FileKey nothing has
// ever named, and can never be resolved to a path.
func (s *session) captureState() error {
	params := ENABLE_TRACE_PARAMETERS{Version: 2}
	r, _, _ := procEnableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&kernelFileProvider)),
		EVENT_CONTROL_CODE_CAPTURE_STATE,
		TRACE_LEVEL_VERBOSE,
		uintptr(keywordsAny), 0, 0,
		uintptr(unsafe.Pointer(&params)),
	)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("EnableTraceEx2(capture state): %w", syscall.Errno(r))
	}
	return nil
}

func (s *session) Stop() {
	if s == nil || s.handle == 0 {
		return
	}
	procControlTraceW.Call(
		uintptr(s.handle),
		0,
		uintptr(unsafe.Pointer(&s.props[0])),
		EVENT_TRACE_CONTROL_STOP,
	)
	s.handle = 0
}

// Lost reports what the session itself dropped, which is different from what the
// consumer failed to keep up with.
//
// known is the point of the third return. Reporting an unanswerable query as
// zero makes "nothing was lost" indistinguishable from "nobody asked", and a
// qualification instrument that cannot tell those apart can only ever produce a
// false green.
func (s *session) Lost() (events, realtimeBuffers uint32, known bool) {
	if s == nil || s.handle == 0 {
		return 0, 0, false
	}
	buf, _ := propertiesBuffer(sessionName, true)
	writeLoggerName(buf, uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})), sessionName)
	r, _, _ := procControlTraceW.Call(
		uintptr(s.handle), 0,
		uintptr(unsafe.Pointer(&buf[0])),
		EVENT_TRACE_CONTROL_QUERY,
	)
	if r != ERROR_SUCCESS {
		return 0, 0, false
	}
	p := (*EVENT_TRACE_PROPERTIES)(unsafe.Pointer(&buf[0]))
	return p.EventsLost, p.RealTimeBuffersLost, true
}

// openAndProcess attaches a consumer to the live session and blocks in
// ProcessTrace until the session stops. The callback runs on ETW's own thread.
func (s *session) openAndProcess(callback uintptr) error {
	logfile := EVENT_TRACE_LOGFILEW{
		LoggerName:       syscall.StringToUTF16Ptr(sessionName),
		ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
		EventCallback:    callback,
	}
	r, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	if uint64(r) == INVALID_PROCESSTRACE_HANDLE {
		return fmt.Errorf("OpenTrace failed")
	}
	s.trace = uint64(r)
	close(s.ready)
	handles := [1]uint64{s.trace}
	rc, _, _ := procProcessTrace.Call(
		uintptr(unsafe.Pointer(&handles[0])), 1, 0, 0,
	)
	procCloseTrace.Call(uintptr(s.trace))
	s.trace = 0
	if rc != ERROR_SUCCESS && rc != ERROR_CTX_CLOSE_PENDING {
		return fmt.Errorf("ProcessTrace: %w", syscall.Errno(rc))
	}
	return nil
}
