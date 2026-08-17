//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"readwatch/internal/eventparse"
	"readwatch/internal/logsink"
	"readwatch/internal/model"
	"readwatch/internal/settings"
)

const (
	EvtSubscribeActionError    = 0
	EvtSubscribeActionDeliver  = 1
	EvtSubscribeToFutureEvents = 1
	EvtRenderEventXML          = 1
)

// source is one way of learning that a file was read. The two mechanisms differ
// only here: everything downstream - folder matching, process exclusion, the
// directory rule, the log and the live feed - is shared, so a change to what
// gets reported cannot apply to one mechanism and not the other.
type source interface {
	Start(cfg settings.Config, selfPID uint32, deliver func(model.Event), onError func(error)) error
	Stop()
	Running() bool
	// Dropped counts what this mechanism failed to deliver. It is surfaced rather
	// than absorbed: a monitor that quietly misses reads is worse than one that
	// says how many it missed.
	Dropped() uint64
}

var (
	evtSubscribeCallbackPtr = syscall.NewCallback(evtSubscribeCallback)
	activeSACLSource        atomic.Pointer[saclSource]
)

// saclSource is the audit-marker mechanism: a subscription to Security 4663,
// which Windows only writes for objects carrying an audit rule ReadWatch put
// there.
type saclSource struct {
	mu      sync.Mutex
	sub     uintptr
	raw     chan string
	stop    chan struct{}
	done    chan struct{}
	selfPID uint32
	deliver func(model.Event)
	onError func(error)
	dropped atomic.Uint64
}

func (s *saclSource) Start(_ settings.Config, selfPID uint32, deliver func(model.Event), onError func(error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sub != 0 {
		return nil
	}
	s.selfPID = selfPID
	s.deliver = deliver
	s.onError = onError
	s.raw = make(chan string, 2048)
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	s.dropped.Store(0)
	activeSACLSource.Store(s)

	channel := utf16Ptr("Security")
	query := utf16Ptr(`*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4663)]]`)
	sub, _, callErr := procEvtSubscribe.Call(
		0, 0, uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(query)), 0, 0,
		evtSubscribeCallbackPtr, EvtSubscribeToFutureEvents,
	)
	if sub == 0 {
		activeSACLSource.Store(nil)
		return winErr("EvtSubscribe(Security/4663)", callErr)
	}
	s.sub = sub
	// Parsed off the subscription callback: that callback runs on the Event Log's
	// own thread and must return quickly.
	go s.parse()
	return nil
}

func (s *saclSource) parse() {
	defer close(s.done)
	for {
		select {
		case raw := <-s.raw:
			event, ok := eventparse.Parse4663(raw)
			if !ok || event.PID == s.selfPID {
				continue
			}
			s.deliver(event)
		case <-s.stop:
			return
		}
	}
}

func (s *saclSource) Stop() {
	s.mu.Lock()
	if s.sub == 0 {
		s.mu.Unlock()
		return
	}
	sub := s.sub
	s.sub = 0
	stop, done := s.stop, s.done
	activeSACLSource.Store(nil)
	procEvtClose.Call(sub)
	close(stop)
	s.mu.Unlock()
	<-done
}

func (s *saclSource) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sub != 0
}

func (s *saclSource) Dropped() uint64 { return s.dropped.Load() }

// EventWatcher is the pipeline every mechanism feeds: it decides what is
// reported, writes the log and drives the live feed.
type EventWatcher struct {
	mu         sync.Mutex
	src        source
	events     chan model.Event
	stop       chan struct{}
	done       chan struct{}
	cfg        settings.Config
	selfPID    uint32
	onEvent    func(model.Event)
	onError    func(error)
	dropped    atomic.Uint64
	suppressed atomic.Uint64
}

func NewEventWatcher(onEvent func(model.Event), onError func(error)) *EventWatcher {
	pid, _, _ := procGetCurrentProcessId.Call()
	return &EventWatcher{selfPID: uint32(pid), onEvent: onEvent, onError: onError}
}

func (w *EventWatcher) Running() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.src != nil
}

// Dropped counts everything that did not reach the log: what this pipeline could
// not keep up with, plus whatever the running mechanism reports losing.
func (w *EventWatcher) Dropped() uint64 {
	w.mu.Lock()
	src := w.src
	w.mu.Unlock()
	n := w.dropped.Load()
	if src != nil {
		n += src.Dropped()
	}
	return n
}

// Suppressed counts reads that matched a folder but were filtered out by the
// exclusion list. Surfaced in the UI so a hidden reader is always visible as a
// number - silently dropping them would defeat the point of the tool.
func (w *EventWatcher) Suppressed() uint64 { return w.suppressed.Load() }

// Start takes the log file rather than its path: the handle was opened under
// the owner's token and duplicated for this watcher, so nothing here resolves a
// name that could have been repointed since it was authorised.
//
// mechanism decides which source runs. Never both at once: an ETW session
// already reports reads on volumes that could carry a marker, so running the two
// together would report every such read twice.
func (w *EventWatcher) Start(cfg settings.Config, logFile *os.File, mechanism settings.Mechanism) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.src != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil
	}
	if len(cfg.Folders) == 0 {
		if logFile != nil {
			_ = logFile.Close()
		}
		return fmt.Errorf("add at least one folder before starting")
	}

	writer, err := logsink.New(logFile, logsink.Format(cfg.LogFormat))
	if err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		return fmt.Errorf("open log: %w", err)
	}

	w.events = make(chan model.Event, 2048)
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	w.cfg = cfg
	w.dropped.Store(0)
	w.suppressed.Store(0)

	var src source
	if mechanism == settings.MechanismETW {
		src = &etwSource{}
	} else {
		src = &saclSource{}
	}
	events := w.events
	deliver := func(e model.Event) {
		select {
		case events <- e:
		default:
			w.dropped.Add(1)
		}
	}
	if err := src.Start(cfg, w.selfPID, deliver, w.onError); err != nil {
		_ = writer.Close()
		return err
	}
	w.src = src
	go w.worker(writer)
	return nil
}

func (w *EventWatcher) Stop() {
	w.mu.Lock()
	if w.src == nil {
		w.mu.Unlock()
		return
	}
	src := w.src
	w.src = nil
	stop := w.stop
	done := w.done
	w.mu.Unlock()
	src.Stop()
	close(stop)
	<-done
}

func (w *EventWatcher) worker(writer *logsink.Writer) {
	defer close(w.done)
	defer writer.Close()
	var flushTimer *time.Timer
	var flushC <-chan time.Time
	armFlush := func() {
		if flushC != nil {
			return
		}
		if flushTimer == nil {
			flushTimer = time.NewTimer(750 * time.Millisecond)
		} else {
			flushTimer.Reset(750 * time.Millisecond)
		}
		flushC = flushTimer.C
	}

	for {
		select {
		case event := <-w.events:
			if event.PID == w.selfPID || !matchesAnyFolder(event.Path, w.cfg.Folders) {
				continue
			}
			// Filtered here, in the service, before the event reaches the log or
			// the pipe: routine background readers can dominate this signal and
			// should cost neither IPC nor UI work.
			if settings.Excludes(w.cfg.ExcludedProcesses, event.ProcessPath, event.Process) {
				w.suppressed.Add(1)
				continue
			}
			attrs, _, _ := procGetFileAttributesW.Call(uintptr(unsafe.Pointer(utf16Ptr(event.Path))))
			if uint32(attrs) != INVALID_FILE_ATTRIBUTES && uint32(attrs)&FILE_ATTRIBUTE_DIRECTORY != 0 {
				event.Directory = true
				if !w.cfg.IncludeDirectories {
					continue
				}
			}
			if event.Time.IsZero() {
				event.Time = time.Now().UTC()
			}
			if err := writer.Write(event); err != nil && w.onError != nil {
				w.onError(err)
			}
			armFlush()
			if w.onEvent != nil {
				w.onEvent(event)
			}
		case <-flushC:
			if err := writer.Flush(); err != nil && w.onError != nil {
				w.onError(err)
			}
			flushC = nil
		case <-w.stop:
			if flushTimer != nil {
				flushTimer.Stop()
			}
			if err := writer.Flush(); err != nil && w.onError != nil {
				w.onError(err)
			}
			return
		}
	}
}

func matchesAnyFolder(path string, folders []string) bool {
	clean := strings.ToLower(filepath.Clean(path))
	for _, folder := range folders {
		root := strings.TrimRight(strings.ToLower(filepath.Clean(folder)), `\/`)
		if clean == root || strings.HasPrefix(clean, root+`\`) || strings.HasPrefix(clean, root+`/`) {
			return true
		}
	}
	return false
}

func evtSubscribeCallback(action, _ uintptr, event uintptr) uintptr {
	s := activeSACLSource.Load()
	if s == nil {
		return 0
	}
	if action == EvtSubscribeActionError {
		if s.onError != nil {
			s.onError(fmt.Errorf("Windows Event Log subscription error: %d", event))
		}
		return 0
	}
	if action != EvtSubscribeActionDeliver {
		return 0
	}
	xml, err := renderEventXML(event)
	if err != nil {
		if s.onError != nil {
			s.onError(err)
		}
		return 0
	}
	select {
	case s.raw <- xml:
	default:
		s.dropped.Add(1)
	}
	return 0
}

func renderEventXML(event uintptr) (string, error) {
	var used, props uint32
	r, _, e := procEvtRender.Call(0, event, EvtRenderEventXML, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r == 0 && used == 0 {
		return "", winErr("EvtRender(size)", e)
	}
	buf := make([]uint16, (used+1)/2)
	r, _, e = procEvtRender.Call(0, event, EvtRenderEventXML, uintptr(used), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r == 0 {
		return "", winErr("EvtRender(XML)", e)
	}
	return syscall.UTF16ToString(buf), nil
}
