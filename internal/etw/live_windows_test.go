//go:build windows

package etw

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestLiveSessionReportsARead is the promotion check for this package: it starts
// a real session and reads a real file. It is gated behind an environment
// variable and skips without it, because starting a machine-wide ETW session is
// not something an ordinary `go test ./...` should do, and it needs elevation.
//
//	READWATCH_ETW_LIVE=1 go test ./internal/etw/ -run Live -v
func TestLiveSessionReportsARead(t *testing.T) {
	if os.Getenv("READWATCH_ETW_LIVE") != "1" {
		t.Skip("set READWATCH_ETW_LIVE=1 and run elevated to exercise a real session")
	}
	dir := `C:\ReadWatch-Test`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot use %s: %v", dir, err)
	}

	var mu sync.Mutex
	var seen []Read
	w := New([]string{dir}, uint32(os.Getpid()), func(r Read) {
		mu.Lock()
		seen = append(seen, r)
		mu.Unlock()
	}, func(err error) { t.Logf("watcher reported: %v", err) })

	if err := w.Start(); err != nil {
		t.Fatalf("start session: %v", err)
	}
	// Stop unconditionally: a session left running is exactly the failure this
	// package is most obliged not to cause.
	defer w.Stop()

	if !w.Running() {
		t.Fatal("Start returned without error but the watcher is not running")
	}

	// A file created and read after the session is up. Its name arrives on the
	// ordinary Create/NameCreate path rather than needing the rundown, so this
	// checks the common case; the parked-and-swept case has its own unit test.
	target := filepath.Join(dir, "live-etw-check.txt")
	if err := os.WriteFile(target, make([]byte, 64*1024), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	defer os.Remove(target)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := readUnbuffered(target); err != nil {
			t.Fatalf("read target: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n > 0 {
			break
		}
	}

	mu.Lock()
	got := append([]Read(nil), seen...)
	mu.Unlock()
	if len(got) == 0 {
		t.Fatalf("no read of %s was reported in 20s; counters: %+v", target, w.Counters())
	}

	var matched *Read
	for i := range got {
		if got[i].Path == target {
			matched = &got[i]
			break
		}
	}
	if matched == nil {
		t.Fatalf("reads were reported but none named %s; first was %+v", target, got[0])
	}
	if matched.PID == 0 {
		t.Error("a read was reported with no process attributed to it")
	}
	if matched.Bytes == 0 {
		t.Error("a read was reported with no bytes; only transfers that moved data should publish")
	}
	if matched.Time.IsZero() {
		t.Error("a read was reported with no timestamp")
	}
	t.Logf("reported %d reads; example %+v; counters %+v", len(got), *matched, w.Counters())
}

// readUnbuffered reads the file in a way that cannot be served from cache.
// An ordinary read of a file just written produces no file-read event at all,
// because nothing reaches the filesystem - which is what made the first version
// of this test fail for a reason that had nothing to do with the watcher.
func readUnbuffered(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil,
		syscall.OPEN_EXISTING, fileFlagNoBuffering, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	// FILE_FLAG_NO_BUFFERING needs a sector-aligned buffer, offset and length.
	// Go does not promise slice alignment, so over-allocate and slice to it.
	raw := make([]byte, 2*sectorAlign)
	off := (sectorAlign - int(uintptr(unsafe.Pointer(&raw[0]))%uintptr(sectorAlign))) % sectorAlign
	buf := raw[off : off+sectorAlign]
	var n uint32
	return syscall.ReadFile(h, buf, &n, nil)
}

const (
	fileFlagNoBuffering = 0x20000000
	sectorAlign         = 4096
)

// TestLiveSessionLeavesNothingBehind proves the session is gone after Stop, and
// that a second watcher can therefore start. If Stop leaked the session, this
// would fail on the ERROR_ALREADY_EXISTS path.
func TestLiveSessionLeavesNothingBehind(t *testing.T) {
	if os.Getenv("READWATCH_ETW_LIVE") != "1" {
		t.Skip("set READWATCH_ETW_LIVE=1 and run elevated to exercise a real session")
	}
	for i := 0; i < 2; i++ {
		w := New([]string{`C:\ReadWatch-Test`}, uint32(os.Getpid()), nil, nil)
		if err := w.Start(); err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		w.Stop()
		if w.Running() {
			t.Fatalf("watcher %d still reports running after Stop", i+1)
		}
	}
}

// TestLiveTeardownNamesAPreOpenedHandle is the regression test for the defect
// that mattered most: the callback used to be disabled before the session was
// stopped, and stopping the session is what provokes the rundown that names a
// handle opened before the session existed. Every one of those names was
// therefore thrown away, and the parking design that exists to use them had
// nothing to work with.
//
// The file here is opened BEFORE the watcher starts and never opened again, so
// its name cannot come from a Create event. If this passes, the teardown path
// really is delivering.
func TestLiveTeardownNamesAPreOpenedHandle(t *testing.T) {
	if os.Getenv("READWATCH_ETW_LIVE") != "1" {
		t.Skip("set READWATCH_ETW_LIVE=1 and run elevated to exercise a real session")
	}
	dir := `C:\ReadWatch-Test`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot use %s: %v", dir, err)
	}
	target := filepath.Join(dir, "live-preopen-check.txt")
	// 512 KB so scattered reads cannot all be served from one buffered fill.
	if err := os.WriteFile(target, make([]byte, 512*1024), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	defer os.Remove(target)

	// Opened before the session, and deliberately never reopened.
	h, err := openUnbuffered(target)
	if err != nil {
		t.Fatalf("pre-open: %v", err)
	}
	defer syscall.CloseHandle(h)

	var mu sync.Mutex
	var seen []Read
	// selfPID 0, not this process: the reads under test are issued by the test
	// itself, and production deliberately drops reads it made. Passing our own id
	// here would filter out the very thing being measured.
	w := New([]string{dir}, 0, func(r Read) {
		mu.Lock()
		seen = append(seen, r)
		mu.Unlock()
	}, func(err error) { t.Logf("watcher reported: %v", err) })

	if err := w.Start(); err != nil {
		t.Fatalf("start session: %v", err)
	}
	// Unconditional: an ETW session outlives the process, so a test that fails
	// before stopping leaves a machine-wide logger running. The previous run of
	// this file did exactly that.
	stopped := false
	defer func() {
		if !stopped {
			w.Stop()
		}
	}()
	started := time.Now()

	// Scattered unbuffered reads through the handle that predates the session.
	buf := make([]byte, 2*sectorAlign)
	off := (sectorAlign - int(uintptr(unsafe.Pointer(&buf[0]))%uintptr(sectorAlign))) % sectorAlign
	page := buf[off : off+sectorAlign]
	// Spread across several seconds. A session that lives for a moment measures
	// delivery latency, not whether teardown names a pre-existing handle.
	for round := 0; round < 6; round++ {
		for i := 0; i < 40; i++ {
			// Scattered across the file so nothing can come from one fill, and
			// sector-aligned because the handle is unbuffered.
			if _, err := syscall.Seek(h, int64(i)*3*sectorAlign, 0); err != nil {
				t.Fatalf("seek %d: %v", i, err)
			}
			var moved uint32
			if err := syscall.ReadFile(h, page, &moved, nil); err != nil && err != syscall.ERROR_HANDLE_EOF {
				t.Fatalf("read %d: %v", i, err)
			}
		}
		time.Sleep(time.Second)
	}

	// The reads have to reach the consumer and be parked before the session is
	// stopped, or the test measures delivery latency rather than teardown naming.
	// The session's flush timer is one second.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		w.rmu.Lock()
		parked := w.deferredHeld
		w.rmu.Unlock()
		if parked > 0 {
			break
		}
	}
	w.rmu.Lock()
	parkedBeforeStop := w.deferredHeld
	w.rmu.Unlock()
	before := w.Counters()
	t.Logf("before Stop: %d reads parked awaiting a name; counters %+v", parkedBeforeStop, before)
	if before.Observed == 0 {
		t.Fatal("no read events reached the consumer at all; the workload is not producing them")
	}
	if parkedBeforeStop == 0 && before.Published == 0 {
		t.Fatal("the pre-opened file's reads were neither parked nor published; nothing for teardown to name")
	}

	// Stop is what provokes the naming. Everything before this point produced no
	// name for this file, which is the whole point.
	w.Stop()
	stopped = true

	mu.Lock()
	got := append([]Read(nil), seen...)
	mu.Unlock()

	var matched int
	for _, r := range got {
		if strings.EqualFold(r.Path, target) {
			matched++
		}
	}
	c := w.Counters()
	t.Logf("session ran %s; %d reads published, %d of them the pre-opened file; counters %+v",
		time.Since(started).Round(time.Millisecond), len(got), matched, c)
	if matched == 0 {
		// Show what the rundown actually delivered. The shape of these names is
		// the whole question: a name that does not start with \Device\ is
		// volume-relative and cannot be matched against a device-rooted watch.
		w.rmu.Lock()
		shown := 0
		for _, m := range []map[uint64]string{w.byRunCur, w.byRunPrev} {
			for k, n := range m {
				if shown >= 8 {
					break
				}
				t.Logf("  rundown name key=0x%X %q", k, n)
				shown++
			}
		}
		for k, n := range w.byKeyCur {
			if shown >= 14 {
				break
			}
			t.Logf("  manifest name key=0x%X %q", k, n)
			shown++
		}
		// The decisive question: is our file's name anywhere in the maps? If it is,
		// naming worked and matching is broken. If it is not, the rundown never
		// named this handle and the coverage claim is what has to change.
		hits := 0
		for _, m := range []map[uint64]string{w.byRunCur, w.byRunPrev, w.byKeyCur, w.byKeyPrev, w.byObjCur, w.byObjPrev} {
			for k, n := range m {
				if strings.Contains(strings.ToLower(n), "live-preopen-check") {
					t.Logf("  FOUND our file in a name map: key=0x%X %q", k, n)
					hits++
				}
			}
		}
		t.Logf("  our file appears in the name maps %d time(s); total rundown names held: %d",
			hits, len(w.byRunCur)+len(w.byRunPrev))
		roots := w.roots
		w.rmu.Unlock()
		for _, r := range roots {
			t.Logf("  watched root nt=%q display=%q", r.nt, r.display)
		}
		t.Fatalf("no read of the pre-opened handle was ever named. counters %+v", c)
	}
	if c.DrainTimeout {
		t.Error("teardown gave up waiting for the trace to finish")
	}
}

// TestLiveSecondWatcherIsRefused proves the one-per-process rule holds against a
// live session rather than only in the abstract. Two watchers sharing the one
// callback would each see part of the stream, which looks like loss with no
// counter to show for it.
func TestLiveSecondWatcherIsRefused(t *testing.T) {
	if os.Getenv("READWATCH_ETW_LIVE") != "1" {
		t.Skip("set READWATCH_ETW_LIVE=1 and run elevated to exercise a real session")
	}
	first := New([]string{`C:\ReadWatch-Test`}, uint32(os.Getpid()), nil, nil)
	if err := first.Start(); err != nil {
		t.Fatalf("first start: %v", err)
	}
	defer first.Stop()

	second := New([]string{`C:\ReadWatch-Test`}, uint32(os.Getpid()), nil, nil)
	if err := second.Start(); err == nil {
		second.Stop()
		t.Fatal("a second watcher started while one was already running")
	}
	if second.Running() {
		t.Error("the refused watcher reports itself as running")
	}
}

func openUnbuffered(path string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil,
		syscall.OPEN_EXISTING, fileFlagNoBuffering, 0)
}
