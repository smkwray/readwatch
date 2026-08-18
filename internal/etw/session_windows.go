//go:build windows

package etw

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// SessionName is deliberately distinctive: an orphan left by a crashed service
// has to be recognisable as ReadWatch's and nothing else's, so that clearing it
// can never stop a session belonging to another product.
const SessionName = "ReadWatchFileRead"

type session struct {
	handle uint64 // TRACEHANDLE from StartTraceW
	mu     sync.Mutex
	trace  uint64 // TRACEHANDLE from OpenTraceW, guarded by mu
	props  []byte
	// ready closes once OpenTraceW has succeeded. A rundown asked for before
	// that is delivered to nobody, and a fixed sleep is not proof of anything.
	ready chan struct{}
}

func (s *session) waitConsumerReady(timeout time.Duration) error {
	select {
	case <-s.ready:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("the ETW consumer did not attach within %s", timeout)
	}
}

// propertiesBuffer lays out EVENT_TRACE_PROPERTIES followed by the logger name,
// which is how Windows expects the name to be passed.
func propertiesBuffer(name string) ([]byte, *EVENT_TRACE_PROPERTIES) {
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
	p.Wnode.Guid = sessionGUID
	p.LoggerNameOffset = uint32(structSize)
	p.LogFileNameOffset = 0
	// 64 KB rather than 1 MB: Microsoft's guidance is that most sessions want
	// 64 KB or less, and a 1 MB x 64-256 envelope would reserve up to 256 MB for
	// what is meant to be a lightweight consumer.
	p.BufferSize = 64
	p.MinimumBuffers = 64
	p.MaximumBuffers = 256
	p.FlushTimer = 1
	p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE
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

// StopStale clears an ETW session left behind by a previous run.
//
// This matters more than it looks. An ETW session is a kernel object that
// outlives the process that created it: a service killed rather than stopped
// leaves the session running, buffering the whole machine's file activity with
// nobody consuming it. Nothing in ETW ties a session's lifetime to its creator,
// so the only defence is to clear an orphan at every point ReadWatch gets
// control - service start as well as monitoring start.
// StopStale clears both of ReadWatch's sessions and confirms each is gone. The
// helper is short-lived only on the happy path: if the process died between
// starting and stopping it, it is still running. Named separately so clearing
// one can never stop the other, and reported so a failure to clean up is visible
// rather than assumed away.
func StopStale() error {
	mainErr := StopStaleVerified()
	helperErr := stopHelper()
	switch {
	case mainErr != nil && helperErr != nil:
		return fmt.Errorf("%w; and %v", mainErr, helperErr)
	case mainErr != nil:
		return mainErr
	default:
		return helperErr
	}
}

// stopStaleSession names the session explicitly, so it can never stop a session
// belonging to anything else.
func stopStaleSession() {
	buf, _ := propertiesBuffer(SessionName)
	writeLoggerName(buf, uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})), SessionName)
	procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SessionName))),
		uintptr(unsafe.Pointer(&buf[0])),
		EVENT_TRACE_CONTROL_STOP,
	)
}

func startSession() (*session, error) {
	if err := CheckLayout(); err != nil {
		return nil, err
	}
	stopStaleSession()

	buf, props := propertiesBuffer(SessionName)
	writeLoggerName(buf, props.LoggerNameOffset, SessionName)

	var handle uint64
	r, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SessionName))),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r != ERROR_SUCCESS {
		if r == ERROR_ALREADY_EXISTS {
			return nil, fmt.Errorf("an ETW session named %s already exists and could not be cleared", SessionName)
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
		uintptr(keywordsLifecycle), 0, enableTimeoutMS,
		uintptr(unsafe.Pointer(&params)),
	)
	if r != ERROR_SUCCESS {
		s.Stop()
		return nil, fmt.Errorf("EnableTraceEx2(enable): %w", syscall.Errno(r))
	}
	return s, nil
}

// enableReads turns on the read keywords once the startup snapshot is in place.
// Until this is called the session sees handle lifetime and filenames but no
// reads, which is what keeps the naming queue from filling with reads nothing
// can name yet.
func (s *session) enableReads() error {
	params := ENABLE_TRACE_PARAMETERS{Version: 2}
	r, _, _ := procEnableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&kernelFileProvider)),
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE,
		uintptr(keywordsFull), 0, enableTimeoutMS,
		uintptr(unsafe.Pointer(&params)),
	)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("EnableTraceEx2(enable reads): %w", syscall.Errno(r))
	}
	return nil
}

// requestRundown asks both providers to describe what they already know: the
// manifest provider for names it holds, and the system logger for the files that
// were open before this session existed.
//
// Neither answers immediately. The records arrive later — measured on this host
// as late as session teardown — which is why unnamed reads are parked rather
// than dropped. See sweep in watcher_windows.go.
func (s *session) requestRundown() error {
	params := ENABLE_TRACE_PARAMETERS{Version: 2}
	r, _, _ := procEnableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&kernelFileProvider)),
		EVENT_CONTROL_CODE_CAPTURE_STATE,
		TRACE_LEVEL_VERBOSE,
		uintptr(keywordsLifecycle), 0, enableTimeoutMS,
		uintptr(unsafe.Pointer(&params)),
	)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("EnableTraceEx2(capture state): %w", syscall.Errno(r))
	}
	return s.requestSystemRundown()
}

// requestSystemRundown directs the classic file rundown at this session.
//
// The filter carries the address of a TRACEHANDLE, and that address is handed to
// Windows as an integer. Go's rules say a uintptr holds no pointer semantics: it
// keeps nothing alive and is not updated if the object moves. Taking the address
// of a stack local here is a real bug — `go build -gcflags=-m=2` confirmed such a
// local "does not escape", so Windows would be given an address on a stack Go may
// grow and relocate, and runtime.KeepAlive does not help because it governs
// finalization, not address validity. runtime.Pinner is the right instrument.
func (s *session) requestSystemRundown() error {
	if s.handle == 0 {
		return fmt.Errorf("rundown requested without a live session")
	}
	target := new(uint64)
	*target = s.handle
	desc := &EVENT_FILTER_DESCRIPTOR{
		Ptr:  uint64(uintptr(unsafe.Pointer(target))),
		Size: uint32(unsafe.Sizeof(*target)),
		Type: EVENT_FILTER_TYPE_TRACEHANDLE,
	}
	params := &ENABLE_TRACE_PARAMETERS{
		Version:          2,
		EnableFilterDesc: unsafe.Pointer(desc),
		FilterDescCount:  1,
	}
	var pin runtime.Pinner
	pin.Pin(target)
	pin.Pin(desc)
	pin.Pin(params)
	defer pin.Unpin()

	r, _, _ := procEnableTraceEx2.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(&systemTraceControlGUID)),
		EVENT_CONTROL_CODE_CAPTURE_STATE,
		0, // the SDK-directed request takes zero level and keywords
		0, 0,
		10_000, // ms, so the provider callback has finished when this returns
		uintptr(unsafe.Pointer(params)),
	)
	if r != ERROR_SUCCESS {
		return fmt.Errorf("EnableTraceEx2(system rundown): %w", syscall.Errno(r))
	}
	return nil
}

// Stop tears the session down. Monitoring-specific resources must not outlive
// monitoring, and an ETW session is one of them.
// Stop tears the session down and says whether it is actually gone. The result
// was previously discarded, which meant "cleanup ran" and "cleanup worked" were
// the same statement - and a session that outlives the process is the one thing
// this package must never leave behind.
func (s *session) Stop() error {
	if s == nil || s.handle == 0 {
		return nil
	}
	r, _, _ := procControlTraceW.Call(
		uintptr(s.handle),
		0,
		uintptr(unsafe.Pointer(&s.props[0])),
		EVENT_TRACE_CONTROL_STOP,
	)
	s.handle = 0
	// Already stopped, or never started, are both the state being asked for.
	switch r {
	case ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, ERROR_CTX_CLOSE_PENDING:
		return nil
	}
	return fmt.Errorf("ControlTrace(stop %s): %w", SessionName, syscall.Errno(r))
}

// StopStaleVerified clears an orphan and confirms it is gone, rather than firing
// a stop and assuming. Reported so a failure to clean up is visible instead of
// silent.
func StopStaleVerified() error { return stopVerified(SessionName, controlStale) }

// stopVerified stops a named session and then keeps asking until Windows says it
// is not there. "Told it to stop" and "it is gone" are different statements, and
// only the second one is cleanup. The distinctions matter: ERROR_MORE_DATA on a
// stop still means the session stopped, ERROR_ACTIVE_CONNECTIONS means it is
// already stopping, and only ERROR_WMI_INSTANCE_NOT_FOUND on a query proves
// absence - any other query error is unknown, not success.
func stopVerified(name string, control func(uintptr) uintptr) error {
	switch r := control(EVENT_TRACE_CONTROL_STOP); r {
	case ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, ERROR_CTX_CLOSE_PENDING,
		ERROR_MORE_DATA, ERROR_ACTIVE_CONNECTIONS:
	default:
		return fmt.Errorf("ControlTrace(stop %s): %w", name, syscall.Errno(r))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		switch r := control(EVENT_TRACE_CONTROL_QUERY); r {
		case ERROR_WMI_INSTANCE_NOT_FOUND:
			return nil
		case ERROR_SUCCESS:
			if time.Now().After(deadline) {
				return fmt.Errorf("an ETW session named %s is still running after being told to stop", name)
			}
			time.Sleep(25 * time.Millisecond)
		default:
			return fmt.Errorf("ControlTrace(query %s): %w", name, syscall.Errno(r))
		}
	}
}

func controlStale(code uintptr) uintptr {
	buf, _ := propertiesBuffer(SessionName)
	writeLoggerName(buf, uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})), SessionName)
	r, _, _ := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SessionName))),
		uintptr(unsafe.Pointer(&buf[0])),
		code,
	)
	return r
}

// Lost reports what the session itself dropped, which is different from what the
// consumer failed to keep up with. known is the point of the third return:
// reporting an unanswerable query as zero makes "nothing was lost"
// indistinguishable from "nobody asked".
func (s *session) Lost() (events, realtimeBuffers uint32, known bool) {
	if s == nil || s.handle == 0 {
		return 0, 0, false
	}
	buf, _ := propertiesBuffer(SessionName)
	writeLoggerName(buf, uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})), SessionName)
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
// token is carried in EVENT_TRACE_LOGFILEW.Context and arrives on every record
// as EVENT_RECORD.UserContext, so a record can be routed to the consumer that
// asked for it rather than to whichever one is current.
func (s *session) openAndProcess(callback uintptr, token unsafe.Pointer) error {
	logfile := EVENT_TRACE_LOGFILEW{
		LoggerName:       syscall.StringToUTF16Ptr(SessionName),
		ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
		EventCallback:    callback,
		Context:          token,
	}
	r, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	if uint64(r) == INVALID_PROCESSTRACE_HANDLE {
		return fmt.Errorf("OpenTrace failed")
	}
	s.mu.Lock()
	s.trace = uint64(r)
	s.mu.Unlock()
	close(s.ready)
	handles := [1]uint64{uint64(r)}
	rc, _, _ := procProcessTrace.Call(
		uintptr(unsafe.Pointer(&handles[0])), 1, 0, 0,
	)
	procCloseTrace.Call(r)
	s.mu.Lock()
	s.trace = 0
	s.mu.Unlock()
	if rc != ERROR_SUCCESS && rc != ERROR_CTX_CLOSE_PENDING {
		return fmt.Errorf("ProcessTrace: %w", syscall.Errno(rc))
	}
	return nil
}

// closeConsumer asks the consumer to stop, which is what a drain that has run
// out of patience needs. Microsoft documents that CloseTrace may be called
// before ProcessTrace returns for a real-time stream, and that
// ERROR_CTX_CLOSE_PENDING means the call succeeded: no further events will be
// delivered, and those already queued are processed before ProcessTrace exits.
func (s *session) closeConsumer() {
	s.mu.Lock()
	h := s.trace
	s.trace = 0
	s.mu.Unlock()
	if h != 0 {
		procCloseTrace.Call(uintptr(h))
	}
}
