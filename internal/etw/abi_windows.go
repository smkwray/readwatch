//go:build windows

// Package etw consumes the Microsoft-Windows-Kernel-File provider to report
// which processes read which files. It is the mechanism ReadWatch uses on
// volumes that cannot carry an audit rule — exFAT and FAT among them — and the
// one the owner can select for any volume.
//
// Every structure here is one Windows writes into, so the sizes and offsets are
// asserted at startup rather than trusted. Two genuine arithmetic errors were
// caught by that check during qualification, before anything was decoded.
package etw

import (
	"fmt"
	"syscall"
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
)

const (
	WNODE_FLAG_TRACED_GUID     = 0x00020000
	EVENT_TRACE_REAL_TIME_MODE = 0x00000100
	// A system logger is what carries the classic FileIo rundown, which is the
	// only thing that can name a file whose handle predates the session.
	EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000

	EVENT_TRACE_FLAG_DISK_IO      = 0x00000100
	EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200
	EVENT_TRACE_FLAG_FILE_IO      = 0x02000000
	EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000

	PROCESS_TRACE_MODE_REAL_TIME    = 0x00000100
	PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000

	EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
	EVENT_CONTROL_CODE_CAPTURE_STATE   = 2

	// EVENT_FILTER_TYPE_TRACEHANDLE names the session a rundown is for, which is
	// what makes it "capture state for me" rather than a broadcast.
	EVENT_FILTER_TYPE_TRACEHANDLE = 0x80000002

	TRACE_LEVEL_VERBOSE = 5

	ERROR_SUCCESS           = 0
	ERROR_ALREADY_EXISTS    = 183
	ERROR_CTX_CLOSE_PENDING = 7007
	// Returned when no session of that name exists, which is the state a stale
	// cleanup is trying to reach rather than a failure to reach it.
	ERROR_WMI_INSTANCE_NOT_FOUND = 4201

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

func (g GUID) equals(o GUID) bool {
	return g.Data1 == o.Data1 && g.Data2 == o.Data2 && g.Data3 == o.Data3 && g.Data4 == o.Data4
}

// kernelFileProvider is {EDD08927-9CC4-4E65-B970-C2560FB5C289}.
var kernelFileProvider = GUID{0xEDD08927, 0x9CC4, 0x4E65, [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}}

// fileIoGUID is the classic MOF provider {90CBDC39-4A3E-11D1-84F4-0000F80464E3}
// the rundown names arrive under. Its event numbering overlaps the manifest
// provider's, so dispatch keys on the provider, never on the number alone.
var fileIoGUID = GUID{0x90CBDC39, 0x4A3E, 0x11D1, [8]byte{0x84, 0xF4, 0x00, 0x00, 0xF8, 0x04, 0x64, 0xE3}}

// systemTraceControlGUID is {9E814AAD-3204-11D2-9A82-006008A86939}, the target
// of the directed rundown request.
var systemTraceControlGUID = GUID{0x9E814AAD, 0x3204, 0x11D2, [8]byte{0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39}}

// sessionGUID identifies ReadWatch's own logger. A multiplexed system logger
// needs a Wnode.Guid that is not SystemTraceControlGuid, or it competes for the
// single legacy NT Kernel Logger instead of getting its own.
var sessionGUID = GUID{0x5A2E1F00, 0x9B41, 0x4C7D, [8]byte{0xA3, 0x11, 0x52, 0x65, 0x61, 0x64, 0x57, 0x32}}

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

type EVENT_FILTER_DESCRIPTOR struct {
	Ptr  uint64
	Size uint32
	Type uint32
}

// CheckLayout fails loudly rather than parsing garbage. A wrong offset in any of
// these is silent corruption, not a compile error, so this runs before the
// session starts and a failure aborts rather than degrades.
func CheckLayout() error {
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
		{"EVENT_RECORD", unsafe.Sizeof(EVENT_RECORD{}), 112},
		{"EVENT_RECORD.UserData offset", unsafe.Offsetof(EVENT_RECORD{}.UserData), 96},
		{"TIME_ZONE_INFORMATION", unsafe.Sizeof(TIME_ZONE_INFORMATION{}), 172},
		{"EVENT_TRACE_HEADER", unsafe.Sizeof(EVENT_TRACE_HEADER{}), 48},
		{"EVENT_TRACE", unsafe.Sizeof(EVENT_TRACE{}), 88},
		{"TRACE_LOGFILE_HEADER", unsafe.Sizeof(TRACE_LOGFILE_HEADER{}), 280},
		{"EVENT_TRACE_LOGFILEW", unsafe.Sizeof(EVENT_TRACE_LOGFILEW{}), 448},
		{"LOGFILEW.CurrentEvent offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.CurrentEvent), 32},
		{"LOGFILEW.LogfileHeader offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.LogfileHeader), 120},
		{"LOGFILEW.BufferCallback offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.BufferCallback), 400},
		{"LOGFILEW.EventCallback offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.EventCallback), 424},
		{"LOGFILEW.Context offset", unsafe.Offsetof(EVENT_TRACE_LOGFILEW{}.Context), 440},
		{"EVENT_FILTER_DESCRIPTOR", unsafe.Sizeof(EVENT_FILTER_DESCRIPTOR{}), 16},
		{"ENABLE_TRACE_PARAMETERS", unsafe.Sizeof(ENABLE_TRACE_PARAMETERS{}), 48},
	} {
		if c.got != c.want {
			return fmt.Errorf("%s is %d bytes, want %d — the ABI is wrong and every field read would be garbage", c.name, c.got, c.want)
		}
	}
	return nil
}
