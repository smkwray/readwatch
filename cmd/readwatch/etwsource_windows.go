//go:build windows

package main

import (
	"strings"
	"sync"
	"syscall"
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
func (s *etwSource) Enrich(e *model.Event) {
	if e.PID == 0 {
		return
	}
	if path, ok := processImagePath(e.PID); ok {
		e.ProcessPath = path
		if i := strings.LastIndexAny(path, `\/`); i >= 0 {
			e.Process = path[i+1:]
		} else {
			e.Process = path
		}
	}
	if name, sid, ok := processUser(e.PID); ok {
		e.User = name
		e.UserSID = sid
	}
}

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
func processImagePath(pid uint32) (string, bool) {
	h, _, _ := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if h == 0 {
		return "", false
	}
	defer procCloseHandle.Call(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, _ := procQueryFullProcessImageNameW.Call(h, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf[:size]), true
}

func processUser(pid uint32) (name, sid string, ok bool) {
	h, _, _ := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if h == 0 {
		return "", "", false
	}
	defer procCloseHandle.Call(h)
	var token HANDLE
	r, _, _ := procOpenProcessToken.Call(h, TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return "", "", false
	}
	defer procCloseHandle.Call(uintptr(token))

	var needed uint32
	procGetTokenInformation.Call(uintptr(token), TokenUser, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return "", "", false
	}
	buf := make([]byte, needed)
	r, _, _ = procGetTokenInformation.Call(uintptr(token), TokenUser,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return "", "", false
	}
	tu := (*TOKEN_USER)(unsafe.Pointer(&buf[0]))

	var sidText *uint16
	if r, _, _ := procConvertSidToStringSidW.Call(tu.User.Sid, uintptr(unsafe.Pointer(&sidText))); r != 0 {
		sid = syscall.UTF16ToString(unsafe.Slice(sidText, sidLen(sidText)))
		procLocalFree.Call(uintptr(unsafe.Pointer(sidText)))
	}
	name = accountNameForSID(tu.User.Sid)
	return name, sid, sid != "" || name != ""
}

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
