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

var (
	evtSubscribeCallbackPtr = syscall.NewCallback(evtSubscribeCallback)
	activeEventWatcher      atomic.Pointer[EventWatcher]
)

type EventWatcher struct {
	mu         sync.Mutex
	sub        uintptr
	raw        chan string
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
	return w.sub != 0
}

func (w *EventWatcher) Dropped() uint64 { return w.dropped.Load() }

// Suppressed counts reads that matched a folder but were filtered out by the
// exclusion list. Surfaced in the UI so a hidden reader is always visible as a
// number - silently dropping them would defeat the point of the tool.
func (w *EventWatcher) Suppressed() uint64 { return w.suppressed.Load() }

// Start takes the log file rather than its path: the handle was opened under
// the owner's token and duplicated for this watcher, so nothing here resolves a
// name that could have been repointed since it was authorised.
func (w *EventWatcher) Start(cfg settings.Config, logFile *os.File) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sub != 0 {
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

	w.raw = make(chan string, 2048)
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	w.cfg = cfg
	w.dropped.Store(0)
	w.suppressed.Store(0)
	activeEventWatcher.Store(w)

	channel := utf16Ptr("Security")
	query := utf16Ptr(`*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4663)]]`)
	sub, _, callErr := procEvtSubscribe.Call(
		0, 0, uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(query)), 0, 0,
		evtSubscribeCallbackPtr, EvtSubscribeToFutureEvents,
	)
	if sub == 0 {
		activeEventWatcher.Store(nil)
		_ = writer.Close()
		return winErr("EvtSubscribe(Security/4663)", callErr)
	}
	w.sub = sub
	go w.worker(writer)
	return nil
}

func (w *EventWatcher) Stop() {
	w.mu.Lock()
	if w.sub == 0 {
		w.mu.Unlock()
		return
	}
	sub := w.sub
	w.sub = 0
	stop := w.stop
	done := w.done
	activeEventWatcher.Store(nil)
	procEvtClose.Call(sub)
	close(stop)
	w.mu.Unlock()
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
		case raw := <-w.raw:
			event, ok := eventparse.Parse4663(raw)
			if !ok || event.PID == w.selfPID || !matchesAnyFolder(event.Path, w.cfg.Folders) {
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
	w := activeEventWatcher.Load()
	if w == nil {
		return 0
	}
	if action == EvtSubscribeActionError {
		if w.onError != nil {
			w.onError(fmt.Errorf("Windows Event Log subscription error: %d", event))
		}
		return 0
	}
	if action != EvtSubscribeActionDeliver {
		return 0
	}
	xml, err := renderEventXML(event)
	if err != nil {
		if w.onError != nil {
			w.onError(err)
		}
		return 0
	}
	select {
	case w.raw <- xml:
	default:
		w.dropped.Add(1)
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
