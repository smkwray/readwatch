//go:build windows

package etw

import (
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// The startup filename snapshot.
//
// The directed rundown does not answer while a session runs. Measured on this
// host: EnableTraceEx2(CAPTURE_STATE) returns ERROR_SUCCESS and emits almost
// nothing, and then 110,000-140,000 FileRundown names arrive at once when the
// session is stopped. A monitor left running for hours would therefore never
// name a handle that was already open when it started - and a database, a
// service or an editor holding a file open is exactly the reader worth noticing.
//
// So a second, short-lived system logger is started and immediately stopped, and
// *its* teardown is used as the snapshot. The main session takes no reads until
// that snapshot is in place, which also keeps its naming queue from filling with
// reads nothing can name yet.

// helperSessionName is distinct from the monitoring session so that clearing one
// can never stop the other, and recognisable as ReadWatch's own.
const helperSessionName = "ReadWatchFileSnapshot"

// helperGUID is the helper's own logger identity. A multiplexed system logger
// needs one that is neither SystemTraceControlGuid nor the main session's.
var helperGUID = GUID{0x5A2E1F01, 0x9B41, 0x4C7D, [8]byte{0xA3, 0x11, 0x52, 0x65, 0x61, 0x64, 0x57, 0x33}}

// snapshotTimeout bounds the whole helper lifecycle. The measured cost on this
// host is well under a second; this is the point at which ReadWatch stops
// waiting and says its startup coverage is degraded rather than blocking a start.
const snapshotTimeout = 30 * time.Second

// snapshot is the collector for one helper run. Its callback runs on ETW's
// thread, so it does nothing but decode and store.
type snapshot struct {
	mu    sync.Mutex
	names map[uint64]string
}

var activeSnapshot struct {
	mu   sync.Mutex
	live *snapshot
}

var snapshotCallback = syscall.NewCallback(onSnapshotEvent)

func onSnapshotEvent(rec *EVENT_RECORD) uintptr {
	activeSnapshot.mu.Lock()
	s := activeSnapshot.live
	activeSnapshot.mu.Unlock()
	if s == nil {
		return 0
	}
	if !rec.EventHeader.ProviderId.equals(fileIoGUID) {
		return 0
	}
	switch rec.EventHeader.EventDescriptor.Opcode {
	case fileIoNameType, fileIoFileCreate, fileIoFileRundown:
		key, name, err := decodeFileIoName(payload(rec))
		if err != nil || key == 0 || name == "" {
			return 0
		}
		s.mu.Lock()
		s.names[key] = name
		s.mu.Unlock()
	case fileIoFileDelete:
		// Deleted while the snapshot was being taken: the identity has stopped
		// meaning this file, so it must not enter the map at all.
		if key, _, err := decodeFileIoName(payload(rec)); err == nil {
			s.mu.Lock()
			delete(s.names, key)
			s.mu.Unlock()
		}
	}
	return 0
}

// takeSnapshot is the seam the degraded path is tested through. Windows allows a
// limited number of system loggers, so a machine already running several can
// refuse this one, and that has to be a reported degradation rather than a
// refusal to monitor. Forcing slot exhaustion on demand is not practical, so the
// failure is injected here instead - the handling is what needs proving, not
// Windows' ability to run out of slots.
var takeSnapshot = snapshotOpenFiles

// snapshotOpenFiles starts a helper system logger, stops it at once, drains its
// teardown enumeration, and returns what it named, keyed by FileKey.
//
// Only one runs at a time, and it is always torn down: an ETW session outlives
// the process that made it, so a helper abandoned here would be the same hazard
// as an abandoned monitoring session.
func snapshotOpenFiles() (map[uint64]string, error) {
	activeSnapshot.mu.Lock()
	if activeSnapshot.live != nil {
		activeSnapshot.mu.Unlock()
		return nil, fmt.Errorf("a filename snapshot is already being taken")
	}
	s := &snapshot{names: make(map[uint64]string, 1<<17)}
	activeSnapshot.live = s
	activeSnapshot.mu.Unlock()
	defer func() {
		activeSnapshot.mu.Lock()
		activeSnapshot.live = nil
		activeSnapshot.mu.Unlock()
	}()

	stopHelperSession()
	buf, props := helperProperties()
	writeLoggerName(buf, props.LoggerNameOffset, helperSessionName)

	var handle uint64
	r, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(helperSessionName))),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r != ERROR_SUCCESS {
		// A system logger slot may simply not be available; Windows allows a
		// limited number. That is a degraded start, not a failure to monitor.
		return nil, fmt.Errorf("StartTrace(%s): %w", helperSessionName, syscall.Errno(r))
	}

	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		logfile := EVENT_TRACE_LOGFILEW{
			LoggerName:       syscall.StringToUTF16Ptr(helperSessionName),
			ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
			EventCallback:    snapshotCallback,
		}
		h, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
		if uint64(h) == INVALID_PROCESSTRACE_HANDLE {
			close(ready)
			done <- fmt.Errorf("OpenTrace(%s) failed", helperSessionName)
			return
		}
		close(ready)
		handles := [1]uint64{uint64(h)}
		rc, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&handles[0])), 1, 0, 0)
		procCloseTrace.Call(h)
		if rc != ERROR_SUCCESS && rc != ERROR_CTX_CLOSE_PENDING {
			done <- fmt.Errorf("ProcessTrace(%s): %w", helperSessionName, syscall.Errno(rc))
			return
		}
		done <- nil
	}()

	<-ready
	// Stopping it is the whole point: the enumeration of open files is what a
	// system logger emits on the way down.
	stopHelperSession()

	select {
	case err := <-done:
		if err != nil {
			return nil, err
		}
	case <-time.After(snapshotTimeout):
		stopHelperSession()
		return nil, fmt.Errorf("the filename snapshot did not finish within %s", snapshotTimeout)
	}

	s.mu.Lock()
	out := s.names
	s.names = nil
	s.mu.Unlock()
	return out, nil
}

func helperProperties() ([]byte, *EVENT_TRACE_PROPERTIES) {
	buf, p := propertiesBuffer(helperSessionName)
	p.Wnode.Guid = helperGUID
	// Only what names files. The helper never consumes reads.
	p.EnableFlags = EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_FILE_IO
	return buf, p
}

func stopHelperSession() {
	buf, _ := helperProperties()
	writeLoggerName(buf, uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})), helperSessionName)
	procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(helperSessionName))),
		uintptr(unsafe.Pointer(&buf[0])),
		EVENT_TRACE_CONTROL_STOP,
	)
}
