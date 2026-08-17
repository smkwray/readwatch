//go:build windows

package etw

import (
	"os"
	"path/filepath"
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
