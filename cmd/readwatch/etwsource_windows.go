//go:build windows

package main

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"readwatch/internal/etw"
	"readwatch/internal/model"
	"readwatch/internal/settings"
)

// etwSource is the event-tracing mechanism behind the same pipeline the audit
// markers feed. It exists so that filtering, exclusion, log writing and the live
// feed cannot behave differently depending on which mechanism is running: one
// conceptual change edits one place.
type etwSource struct {
	// mu guards w. Stop clears it while the window may be asking for counters,
	// and those two run on different goroutines.
	mu sync.Mutex
	w  *etw.Watcher
	// roots are what the binder proved, carried in rather than re-derived.
	roots []etw.BoundRoot
}

func (s *etwSource) watcher() *etw.Watcher {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w
}

func (s *etwSource) Start(cfg settings.Config, selfPID uint32, deliver func(model.Event), onError func(error)) error {
	// Only what the provider hands over. Naming the process costs two syscalls
	// and this callback runs on ETW's own thread, where anything slow shows up as
	// lost events rather than as latency. The rest is filled in by Enrich.
	roots := s.roots
	if len(roots) == 0 {
		// No proven roots were handed over. Resolving the configured paths here
		// would reintroduce exactly the bind-to-start remapping window the bound
		// roots exist to close, so this is a refusal rather than a fallback.
		return fmt.Errorf("no bound watch roots were provided to the tracing source")
	}
	w := etw.New(roots, selfPID, func(r etw.Read) {
		deliver(model.Event{Time: r.Time, Path: r.Path, PID: r.PID})
	}, onError)
	if err := w.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.w = w
	s.mu.Unlock()
	return nil
}

// Enrich names the process behind a read. ETW reports a process id and nothing
// else about it, so the executable is resolved here - on the pipeline's
// goroutine, after the folder filter, so the cost is paid only for reads the
// owner asked about and never for the machine-wide stream.
//
// User and UserSID are deliberately left empty in this mode. Filling them meant
// opening the security token of every process that reads a watched file, and
// what this tool promises is to name the *process*, not the account behind it.
// That is a real loss - the marker mechanism still reports the user - but
// reading other processes' tokens is the most surveillance-shaped thing the
// program did, for the least of what it exists to tell you.
//
// Resolved per event rather than cached by pid on purpose. Windows reuses
// process ids, and a stale cache entry would attribute a read to whatever
// process previously held that number. Naming the wrong process is the one
// mistake this tool must not make.
func (s *etwSource) Stop() {
	s.mu.Lock()
	w := s.w
	s.w = nil
	s.mu.Unlock()
	if w != nil {
		w.Stop()
	}
}

func (s *etwSource) Running() bool {
	w := s.watcher()
	return w != nil && w.Running()
}

// Dropped reports everything this mechanism failed to deliver, from either side:
// what the session lost and what correlation could not name. Reporting only one
// would make a monitor that is missing reads look healthy.
func (s *etwSource) Dropped() uint64 {
	w := s.watcher()
	if w == nil {
		return 0
	}
	c := w.Counters()
	return c.Dropped + c.NeverNamed + c.SessionLost
}

// Losses names each way a read failed to reach the log. They are kept apart
// because they have different causes and different fixes: a session that lost
// buffers is not the same problem as a correlation that could not name a file.
func (s *etwSource) Losses() map[string]uint64 {
	w := s.watcher()
	if w == nil {
		return nil
	}
	c := w.Counters()
	out := map[string]uint64{}
	add := func(name string, n uint64) {
		if n > 0 {
			out[name] = n
		}
	}
	add("events the trace session dropped", c.SessionLost)
	add("trace buffers lost", c.BuffersLost)
	add("reads the consumer could not keep up with", c.Dropped)
	add("reads whose file could not be named", c.NeverNamed)
	add("reads whose completion never arrived", c.Expired)
	add("operations sharing a reused identifier", c.Collisions)
	add("reads beyond one file's share of the naming queue", c.Crowded)
	add("filenames the bounded map could not admit", c.NamesRejected)
	if c.FenceTimedOut {
		add("startup filename snapshot merged without confirming the stream had caught up", 1)
	}
	if c.SnapshotFailed {
		add("no startup filename snapshot; files already open may be unnamed until monitoring stops", 1)
	}
	add("watched folders whose volume could not be resolved", c.UnboundRoots)
	if c.DrainTimeout {
		add("teardown stopped waiting for the trace to finish", 1)
	}
	return out
}

func (s *etwSource) Enrich(e *model.Event) {
	if e.PID == 0 {
		return
	}
	image, ok := processIdentity(e.PID, e.Time)
	if !ok {
		// The process could not be proven to be the one that read the file.
		// Leaving these blank is the honest answer; filling them in from whoever
		// holds the id now is how a read gets attributed to an innocent process.
		return
	}
	e.ProcessPath = image
	if i := strings.LastIndexAny(image, `\/`); i >= 0 {
		e.Process = image[i+1:]
	} else {
		e.Process = image
	}
}

// processIdentity describes the process behind a read, or refuses to.
//
// The handle's creation time is checked against the time of the read: a process
// that started after the read cannot be the one that made it, which is precisely
// the reused-id case. Enrichment happens after the deferred sweep, so that gap
// can be seconds wide.
func processIdentity(pid uint32, at time.Time) (image string, ok bool) {
	h, _, _ := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if h == 0 {
		return "", false
	}
	defer procCloseHandle.Call(h)

	if !startedBefore(h, at) {
		return "", false
	}

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if r, _, _ := procQueryFullProcessImageNameW.Call(h, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", false
	}
	image = syscall.UTF16ToString(buf[:size])
	return image, image != ""
}

// startedBefore reports whether this process existed when the read happened. An
// unreadable creation time is treated as a refusal rather than a pass: an
// unverifiable identity is exactly the case this exists to catch.
func startedBefore(h uintptr, at time.Time) bool {
	var creation, exit, kernel, user FILETIME
	r, _, _ := procGetProcessTimes.Call(h,
		uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return false
	}
	if at.IsZero() {
		return true
	}
	const windowsToUnixEpoch100ns = 116444736000000000
	ticks := int64(creation.Uint64())
	if ticks <= windowsToUnixEpoch100ns {
		return false
	}
	started := time.Unix(0, (ticks-windowsToUnixEpoch100ns)*100).UTC()
	// Fail closed. A process that started after the event cannot have issued it,
	// and a second of slack is a second in which a reused id names a replacement
	// process. Equality is still accepted, for clock rounding.
	return !started.After(at)
}

const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

// processImagePath names the executable behind a process id. A process that has
// already exited cannot be described, which is an ordinary outcome for a
// short-lived reader rather than an error to report: the read still happened and
// is still reported, with the fields that could not be filled left empty rather
// than guessed at.
