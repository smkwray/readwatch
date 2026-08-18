//go:build windows

package main

import (
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
	w := etw.New(cfg.Folders, selfPID, func(r etw.Read) {
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
// else about the process, so the image and the user are resolved here - on the
// pipeline's goroutine, after the folder filter, so the cost is paid only for
// reads the owner asked about and never for the machine-wide stream.
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
	image, user, sid, ok := processIdentity(e.PID, e.Time)
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
	e.User = user
	e.UserSID = sid
}

// processIdentity describes the process behind a read, or refuses to.
//
// One handle answers both questions. Opening twice - once for the image, once
// for the token - can observe two different occupants of the same id, and
// windows reuses process ids freely. The handle's creation time is then checked
// against the time of the read: a process that started after the read cannot be
// the one that made it, which is precisely the reused-id case. Enrichment
// happens after the deferred sweep, so that gap can be seconds wide.
func processIdentity(pid uint32, at time.Time) (image, user, sid string, ok bool) {
	h, _, _ := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if h == 0 {
		return "", "", "", false
	}
	defer procCloseHandle.Call(h)

	if !startedBefore(h, at) {
		return "", "", "", false
	}

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if r, _, _ := procQueryFullProcessImageNameW.Call(h, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", "", "", false
	}
	image = syscall.UTF16ToString(buf[:size])
	user, sid = tokenUser(h)
	return image, user, sid, image != ""
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
	// A second of slack: the event clock and the process clock are both system
	// time, but a read logged at the same instant a process starts should not be
	// discarded over rounding.
	return !started.After(at.Add(time.Second))
}

func tokenUser(process uintptr) (name, sid string) {
	var token HANDLE
	if r, _, _ := procOpenProcessToken.Call(process, TOKEN_QUERY, uintptr(unsafe.Pointer(&token))); r == 0 {
		return "", ""
	}
	defer procCloseHandle.Call(uintptr(token))

	var needed uint32
	procGetTokenInformation.Call(uintptr(token), TokenUser, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return "", ""
	}
	buf := make([]byte, needed)
	if r, _, _ := procGetTokenInformation.Call(uintptr(token), TokenUser,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed))); r == 0 {
		return "", ""
	}
	tu := (*TOKEN_USER)(unsafe.Pointer(&buf[0]))

	var sidText *uint16
	if r, _, _ := procConvertSidToStringSidW.Call(tu.User.Sid, uintptr(unsafe.Pointer(&sidText))); r != 0 {
		sid = syscall.UTF16ToString(unsafe.Slice(sidText, sidLen(sidText)))
		procLocalFree.Call(uintptr(unsafe.Pointer(sidText)))
	}
	return accountNameForSID(tu.User.Sid), sid
}

// sidLen measures a null-terminated wide string LocalAlloc'd by Windows, so it
// can be copied into Go memory before being freed.
func sidLen(p *uint16) int {
	if p == nil {
		return 0
	}
	n := 0
	for ; n < 1024; n++ {
		if *(*uint16)(unsafe.Add(unsafe.Pointer(p), n*2)) == 0 {
			break
		}
	}
	return n
}

const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

// processImagePath names the executable behind a process id. A process that has
// already exited cannot be described, which is an ordinary outcome for a
// short-lived reader rather than an error to report: the read still happened and
// is still reported, with the fields that could not be filled left empty rather
// than guessed at.

// accountNameForSID renders DOMAIN\user. An unresolvable SID is left empty
// rather than filled with a placeholder: the SID itself is already reported, and
// inventing a name would be worse than showing none.
func accountNameForSID(sid uintptr) string {
	var nameLen, domainLen uint32
	var use uint32
	procLookupAccountSidW.Call(0, sid, 0, uintptr(unsafe.Pointer(&nameLen)),
		0, uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&use)))
	if nameLen == 0 {
		return ""
	}
	name := make([]uint16, nameLen)
	domain := make([]uint16, domainLen+1)
	r, _, _ := procLookupAccountSidW.Call(0, sid,
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&use)))
	if r == 0 {
		return ""
	}
	d := syscall.UTF16ToString(domain)
	n := syscall.UTF16ToString(name)
	if d == "" {
		return n
	}
	return d + `\` + n
}
