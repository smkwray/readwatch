//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"readwatch/internal/model"
	"readwatch/internal/protocol"
	"readwatch/internal/settings"
)

// The service-level gates. These drive the installed service over its own IPC,
// as the owner, which is the only way to exercise what package-level tests
// cannot: that the whole pipeline reports a read, that switching mechanism
// strands nothing, and that the log receives what the viewer was shown.
//
// They replace the owner's watched folders while they run, so the original
// configuration is captured first and restored unconditionally - including when
// a test fails part way. Gated, because they need a running service and they
// disturb live settings:
//
//	READWATCH_SERVICE_TESTS=1 go test ./cmd/readwatch/ -run ServiceLevel -v
type serviceHarness struct {
	t        *testing.T
	client   *IPCClient
	mu       sync.Mutex
	states   []protocol.State
	events   []model.Event
	original settings.PublicConfig
}

func newServiceHarness(t *testing.T) *serviceHarness {
	t.Helper()
	if os.Getenv("READWATCH_SERVICE_TESTS") != "1" {
		t.Skip("set READWATCH_SERVICE_TESTS=1 with ReadWatch installed and running")
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current user SID: %v", err)
	}
	h := &serviceHarness{t: t}
	first := make(chan protocol.State, 1)
	h.client, err = ConnectIPC(sid, protocol.RoleViewer, 10*time.Second,
		func(s protocol.State) {
			h.mu.Lock()
			h.states = append(h.states, s)
			h.mu.Unlock()
			select {
			case first <- s:
			default:
			}
		},
		func(e model.Event) {
			h.mu.Lock()
			h.events = append(h.events, e)
			h.mu.Unlock()
		}, nil)
	if err != nil {
		t.Skipf("cannot reach the service: %v", err)
	}
	select {
	case s := <-first:
		h.original = s.Config
	case <-time.After(10 * time.Second):
		h.client.Close()
		t.Fatal("the service sent no state in 10s")
	}
	t.Logf("captured the owner's configuration: %d folders, log %q", len(h.original.Folders), h.original.LogPath)

	t.Cleanup(func() {
		// Unconditional, and in this order: stop first so nothing is running
		// against the test configuration, then put the owner's settings back.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := h.client.Command(ctx, protocol.CmdStop, nil, false); err != nil {
			t.Errorf("restoring: stop failed: %v", err)
		}
		restore := h.original
		if err := h.client.Command(ctx, protocol.CmdApply, &restore, true); err != nil {
			t.Errorf("RESTORING THE OWNER CONFIGURATION FAILED: %v", err)
		} else {
			t.Logf("restored the owner configuration")
		}
		h.client.Close()
	})
	return h
}

func (h *serviceHarness) do(command string, cfg *settings.PublicConfig, authorise bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return h.client.Command(ctx, command, cfg, authorise)
}

// awaitState waits for a state satisfying want, asking for a fresh one as it
// goes, and returns the first that matched.
func (h *serviceHarness) awaitState(want func(protocol.State) bool, timeout time.Duration, why string) protocol.State {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		for i := len(h.states) - 1; i >= 0; i-- {
			if want(h.states[i]) {
				s := h.states[i]
				h.mu.Unlock()
				return s
			}
		}
		last := len(h.states)
		h.mu.Unlock()
		_ = last
		if err := h.do(protocol.CmdGetState, nil, false); err != nil {
			h.t.Fatalf("%s: get_state: %v", why, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	h.mu.Lock()
	var lastSeen protocol.State
	if n := len(h.states); n > 0 {
		lastSeen = h.states[n-1]
	}
	h.mu.Unlock()
	h.t.Fatalf("%s: no state matched within %s; last was running=%v mechanism=%q error=%q",
		why, timeout, lastSeen.Running, lastSeen.Mechanism, lastSeen.LastError)
	return protocol.State{}
}

func (h *serviceHarness) eventsUnder(dir string) []model.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []model.Event
	for _, e := range h.events {
		if strings.HasPrefix(strings.ToLower(e.Path), strings.ToLower(dir)) {
			out = append(out, e)
		}
	}
	return out
}

// TestServiceLevelExFATEndToEnd is the owner test, driven through the service:
// watch a folder on the exFAT stick, confirm the service selects event tracing
// and says so, confirm reads reach both the viewer and the log, then stop.
func TestServiceLevelExFATEndToEnd(t *testing.T) {
	h := newServiceHarness(t)

	dir := exfatTestDir(t)
	logDir := t.TempDir()
	logPath := filepath.Join(logDir, "servicelevel.log")

	cfg := h.original
	cfg.Folders = []string{dir}
	cfg.LogPath = logPath
	cfg.Mechanism = settings.MechanismAuto
	cfg.Enabled = true
	if err := h.do(protocol.CmdApply, &cfg, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := h.do(protocol.CmdStart, nil, false); err != nil {
		t.Fatalf("start: %v", err)
	}

	s := h.awaitState(func(s protocol.State) bool { return s.Running }, 90*time.Second, "waiting for monitoring")
	if s.Mechanism != string(settings.MechanismETW) {
		t.Fatalf("mechanism is %q, want event tracing: an exFAT folder cannot carry a marker. reason=%q",
			s.Mechanism, s.MechanismReason)
	}
	t.Logf("mechanism %q - %s", s.Mechanism, s.MechanismReason)
	for _, f := range s.Folders {
		t.Logf("folder %s state=%v detail=%q", f.Path, f.State, f.Detail)
		if strings.EqualFold(f.Path, dir) && f.State != protocol.FolderAvailable {
			t.Fatalf("the exFAT folder is %v rather than watched: %s", f.State, f.Detail)
		}
	}

	target := filepath.Join(dir, "servicelevel-read.txt")
	if err := os.WriteFile(target, make([]byte, 128*1024), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	defer os.Remove(target)

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := readUnbufferedFile(target); err != nil {
			t.Fatalf("read target: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
		if len(h.eventsUnder(dir)) > 0 {
			break
		}
	}
	got := h.eventsUnder(dir)
	if len(got) == 0 {
		t.Fatalf("no read under %s reached the viewer in 60s", dir)
	}
	t.Logf("viewer received %d reads; first %+v", len(got), got[0])

	// Stopping must flush the log. A read the viewer saw has to be on disk too.
	if err := h.do(protocol.CmdStop, nil, false); err != nil {
		t.Fatalf("stop: %v", err)
	}
	h.awaitState(func(s protocol.State) bool { return !s.Running }, 60*time.Second, "waiting for stop")

	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("the log the service was told to write does not exist: %v", err)
	}
	if !strings.Contains(strings.ToLower(string(b)), strings.ToLower(filepath.Base(target))) {
		t.Fatalf("the log does not mention %s, so events reached the viewer and not the disk:\n%s",
			filepath.Base(target), truncateForLog(string(b), 2000))
	}
	t.Logf("the log carried the read as well as the viewer (%d bytes)", len(b))
}

// TestServiceLevelMechanismSwitch moves a running session from tracing to
// markers and back. That transition is where privileged state is most likely to
// be stranded, in either direction.
func TestServiceLevelMechanismSwitch(t *testing.T) {
	h := newServiceHarness(t)
	exfat := exfatTestDir(t)

	ntfs := `C:\ReadWatch-Test`
	if err := os.MkdirAll(ntfs, 0o755); err != nil {
		t.Skipf("cannot use %s: %v", ntfs, err)
	}
	logPath := filepath.Join(t.TempDir(), "switch.log")

	cfg := h.original
	cfg.Folders = []string{exfat}
	cfg.LogPath = logPath
	cfg.Mechanism = settings.MechanismAuto
	cfg.Enabled = true
	if err := h.do(protocol.CmdApply, &cfg, true); err != nil {
		t.Fatalf("apply exFAT: %v", err)
	}
	if err := h.do(protocol.CmdStart, nil, false); err != nil {
		t.Fatalf("start: %v", err)
	}
	s := h.awaitState(func(s protocol.State) bool { return s.Running }, 90*time.Second, "start on exFAT")
	if s.Mechanism != string(settings.MechanismETW) {
		t.Fatalf("expected event tracing on exFAT, got %q", s.Mechanism)
	}

	// An NTFS-only configuration while running: markers become possible.
	cfg.Folders = []string{ntfs}
	if err := h.do(protocol.CmdApply, &cfg, true); err != nil {
		t.Fatalf("apply NTFS: %v", err)
	}
	s = h.awaitState(func(s protocol.State) bool {
		return s.Running && s.Mechanism == string(settings.MechanismMarkers)
	}, 90*time.Second, "switch to markers")
	t.Logf("switched to %q - %s", s.Mechanism, s.MechanismReason)

	// And back. If the marker path stranded anything, this is where it shows.
	cfg.Folders = []string{exfat}
	if err := h.do(protocol.CmdApply, &cfg, true); err != nil {
		t.Fatalf("apply exFAT again: %v", err)
	}
	s = h.awaitState(func(s protocol.State) bool {
		return s.Running && s.Mechanism == string(settings.MechanismETW)
	}, 90*time.Second, "switch back to tracing")
	t.Logf("switched back to %q", s.Mechanism)
	if len(s.PendingRules) > 0 {
		t.Errorf("switching left audit rules ReadWatch still owns: %v", s.PendingRules)
	}

	if err := h.do(protocol.CmdStop, nil, false); err != nil {
		t.Fatalf("stop: %v", err)
	}
	s = h.awaitState(func(s protocol.State) bool { return !s.Running }, 60*time.Second, "stop")
	if len(s.PendingRules) > 0 {
		t.Errorf("stopping left audit rules ReadWatch still owns: %v", s.PendingRules)
	}
}

func exfatTestDir(t *testing.T) string {
	t.Helper()
	for letter := 'A'; letter <= 'Z'; letter++ {
		root := string(letter) + `:\`
		if driveType(root) == DRIVE_NO_ROOT_DIR {
			continue
		}
		traits, err := volumeTraitsFor(root)
		if err != nil || !strings.EqualFold(traits.FileSystem, "exFAT") {
			continue
		}
		dir := filepath.Join(root, "ReadWatch-USB-Test")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		return dir
	}
	t.Skip("no writable exFAT volume mounted; this gate needs one")
	return ""
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// TestServiceLevelMarkersCatchFilesCreatedAfterStart answers a question the
// README could only assert: audit markers are described as marking the files in
// a watched folder when monitoring starts, which sounds like a snapshot. If it
// were one, a file created afterwards would never be reported - which would make
// the mechanism close to useless for a folder that is being written to.
//
// The audit entry is applied inheritable, so Windows should give it to new files
// as they are created. This proves it rather than trusting the flag.
func TestServiceLevelMarkersCatchFilesCreatedAfterStart(t *testing.T) {
	h := newServiceHarness(t)

	dir := `C:\ReadWatch-Test`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot use %s: %v", dir, err)
	}
	logPath := filepath.Join(t.TempDir(), "inherit.log")

	cfg := h.original
	cfg.Folders = []string{dir}
	cfg.LogPath = logPath
	cfg.Mechanism = settings.MechanismMarkers
	cfg.Enabled = true
	if err := h.do(protocol.CmdApply, &cfg, true); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := h.do(protocol.CmdStart, nil, false); err != nil {
		t.Fatalf("start: %v", err)
	}
	s := h.awaitState(func(s protocol.State) bool { return s.Running }, 90*time.Second, "start with markers")
	if s.Mechanism != string(settings.MechanismMarkers) {
		t.Skipf("this run selected %q, not markers; nothing to prove here", s.Mechanism)
	}

	// Created strictly after monitoring began.
	target := filepath.Join(dir, "created-after-start.txt")
	if err := os.WriteFile(target, make([]byte, 64*1024), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	defer os.Remove(target)

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := readUnbufferedFile(target); err != nil {
			t.Fatalf("read target: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
		for _, e := range h.eventsUnder(dir) {
			if strings.EqualFold(e.Path, target) {
				t.Logf("a file created after monitoring started was reported: %+v", e)
				return
			}
		}
	}
	t.Fatalf("no read of %s was reported in 60s; a file created after start went unwatched, "+
		"which would mean the marker is a snapshot rather than inherited", target)
}
