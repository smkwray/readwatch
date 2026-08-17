//go:build windows

package etw

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

func TestCheckLayoutPasses(t *testing.T) {
	// If this fails, every field read from a Windows structure is garbage, so it
	// is the one check that must run before anything else in the package.
	if err := CheckLayout(); err != nil {
		t.Fatal(err)
	}
}

// utf16Bytes builds a null-terminated UTF-16 payload tail the way the provider
// does, so the decoders are exercised against the shape they actually receive.
func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2+2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return append(b, 0, 0)
}

func TestDecodersFailClosedOnShortPayload(t *testing.T) {
	// A payload shorter than the declared layout means an unexpected version.
	// Parsing it by positional guesswork would attribute a read to whatever
	// happened to be at the offset, so every decoder must refuse instead.
	cases := []struct {
		name string
		fn   func([]byte) error
		size int
	}{
		{"read", func(b []byte) error { _, err := decodeRead(b); return err }, readFixedLen},
		{"name", func(b []byte) error { _, err := decodeName(b); return err }, 8},
		{"create", func(b []byte) error { _, err := decodeCreate(b); return err }, 32},
		{"opEnd", func(b []byte) error { _, err := decodeOpEnd(b); return err }, 20},
		{"close", func(b []byte) error { _, err := decodeClose(b); return err }, 24},
		{"fileIoName", func(b []byte) error { _, _, err := decodeFileIoName(b); return err }, 8},
	}
	for _, c := range cases {
		if err := c.fn(make([]byte, c.size-1)); err != errShort {
			t.Errorf("%s: one byte short accepted, want errShort, got %v", c.name, err)
		}
		if err := c.fn(nil); err != errShort {
			t.Errorf("%s: nil payload accepted, want errShort, got %v", c.name, err)
		}
	}
}

func TestDecodeReadLayout(t *testing.T) {
	// The offsets here are not from documentation: they were read out of a raw
	// dump of real events on this host. A schema-derived guess put FileKey at 32,
	// which lands on the thread id and size, not a pointer at all.
	b := make([]byte, readFixedLen)
	binary.LittleEndian.PutUint64(b[0:], 0x1111111111111111)  // ByteOffset
	binary.LittleEndian.PutUint64(b[8:], 0x2222222222222222)  // Irp
	binary.LittleEndian.PutUint64(b[16:], 0x3333333333333333) // FileObject
	binary.LittleEndian.PutUint64(b[24:], 0x4444444444444444) // FileKey
	binary.LittleEndian.PutUint32(b[32:], 0x55555555)         // IssuingThreadId
	binary.LittleEndian.PutUint32(b[36:], 0x66666666)         // IOSize

	r, err := decodeRead(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Irp != 0x2222222222222222 || r.FileObject != 0x3333333333333333 ||
		r.FileKey != 0x4444444444444444 || r.IssuingThreadID != 0x55555555 {
		t.Fatalf("read decoded wrong: %+v", r)
	}
}

func TestDecodeOpEndLayout(t *testing.T) {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint64(b[0:], 0xABCD)
	binary.LittleEndian.PutUint64(b[8:], 4096) // ExtraInformation: bytes transferred
	binary.LittleEndian.PutUint32(b[16:], 0)   // STATUS_SUCCESS
	o, err := decodeOpEnd(b)
	if err != nil {
		t.Fatal(err)
	}
	if o.Irp != 0xABCD || o.ExtraInformation != 4096 || o.Status != 0 {
		t.Fatalf("opEnd decoded wrong: %+v", o)
	}
}

func TestDecodeFileIoNameCarriesTheJoinKey(t *testing.T) {
	// The value this returns is what a manifest Read carries as its FileKey.
	// That equality is what makes a handle opened before the session nameable.
	b := append(make([]byte, 8), utf16Bytes(`\Device\HarddiskVolume3\x.txt`)...)
	binary.LittleEndian.PutUint64(b[0:], 0xFFFFA5025A725180)
	key, name, err := decodeFileIoName(b)
	if err != nil {
		t.Fatal(err)
	}
	if key != 0xFFFFA5025A725180 {
		t.Fatalf("join key decoded as 0x%X", key)
	}
	if name != `\Device\HarddiskVolume3\x.txt` {
		t.Fatalf("name decoded as %q", name)
	}
}

func TestMatchVolume(t *testing.T) {
	vols := map[string]string{
		`\Device\HarddiskVolume1`:  "C:",
		`\Device\HarddiskVolume11`: "D:",
	}
	cases := []struct {
		nt   string
		want string
	}{
		{`\Device\HarddiskVolume1\a\b.txt`, `C:\a\b.txt`},
		{`\Device\HarddiskVolume11\a.txt`, `D:\a.txt`},
		{`\Device\HarddiskVolume1`, "C:"},
		// A volume number that merely starts with another's must not be captured
		// by it: HarddiskVolume11 is not inside HarddiskVolume1.
		{`\Device\HarddiskVolume111\a.txt`, ""},
		{`\Device\Mup\server\share\a.txt`, ""},
		// Windows is case-insensitive here and the provider's casing is not
		// guaranteed to match QueryDosDevice's.
		{`\device\harddiskvolume1\A.TXT`, `C:\A.TXT`},
	}
	for _, c := range cases {
		got, _ := matchVolume(vols, c.nt)
		if got != c.want {
			t.Errorf("matchVolume(%q) = %q, want %q", c.nt, got, c.want)
		}
	}
}

func TestWantedRejectsSiblingPrefix(t *testing.T) {
	w := New([]string{`C:\Watched`, `D:\`}, 0, nil, nil)
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Watched\a.txt`, true},
		{`C:\Watched`, true},
		{`c:\watched\SUB\a.txt`, true},
		// The reason this test exists: a prefix match without the separator would
		// report reads of an unwatched folder as if the owner had asked for them.
		{`C:\WatchedElsewhere\a.txt`, false},
		{`C:\Other\a.txt`, false},
		{`D:\anything\a.txt`, true},
	}
	for _, c := range cases {
		if got := w.wanted(c.path); got != c.want {
			t.Errorf("wanted(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestWantedWithNoFoldersEmitsNothing(t *testing.T) {
	w := New(nil, 0, nil, nil)
	if w.wanted(`C:\anything`) {
		t.Fatal("an empty watch list matched a path; it must match nothing")
	}
}

// newTestWatcher builds a watcher with correlation state and a fixed volume map,
// so the parking and sweep path can be exercised without opening a session.
func newTestWatcher(t *testing.T, keep []string, emit func(Read)) *Watcher {
	t.Helper()
	w := New(keep, 0, emit, nil)
	w.initState()
	w.rmu.Lock()
	w.volumes = map[string]string{`\Device\HarddiskVolume3`: "C:"}
	w.volumesAt = time.Now()
	w.rmu.Unlock()
	return w
}

func TestParkedReadIsNamedByALaterRundown(t *testing.T) {
	// This is the whole design. A read of a handle opened before the session
	// completes with a FileKey nothing has named yet. The name arrives later -
	// measured on this host as late as session teardown - and the read must still
	// be attributed rather than discarded at completion.
	var got []Read
	w := newTestWatcher(t, []string{`C:\Watched`}, func(r Read) { got = append(got, r) })

	const key = 0xFFFFA5025A725180
	w.park(pendingRead{fileKey: key, pid: 4242, bytes: 4096, at: time.Now().UTC()})

	w.sweepDeferred(false)
	if len(got) != 0 {
		t.Fatalf("a read was published before anything named its file: %+v", got)
	}
	if n := w.neverNamed.Load(); n != 0 {
		t.Fatalf("a non-final sweep gave up on a read: neverNamed=%d", n)
	}

	// The rundown answers.
	w.learn(&w.byRunCur, key, `\Device\HarddiskVolume3\Watched\late.txt`)
	w.sweepDeferred(false)

	if len(got) != 1 {
		t.Fatalf("expected the read to be published once the name arrived, got %d", len(got))
	}
	if got[0].Path != `C:\Watched\late.txt` || got[0].PID != 4242 || got[0].Bytes != 4096 {
		t.Fatalf("published the wrong read: %+v", got[0])
	}
}

func TestFinalSweepCountsWhatWasNeverNamed(t *testing.T) {
	// A read that never gets a name is counted, never invented and never hidden.
	w := newTestWatcher(t, []string{`C:\Watched`}, func(Read) {
		t.Error("published a read whose file was never named")
	})
	w.park(pendingRead{fileKey: 0xDEAD, pid: 7, bytes: 1})
	w.sweepDeferred(false)
	if w.neverNamed.Load() != 0 {
		t.Fatal("a non-final sweep counted a read as never named; its name may still be coming")
	}
	w.sweepDeferred(true)
	if got := w.neverNamed.Load(); got != 1 {
		t.Fatalf("final sweep counted %d never-named reads, want 1", got)
	}
}

func TestParkedReadOutsideWatchedFoldersIsNotPublished(t *testing.T) {
	w := newTestWatcher(t, []string{`C:\Watched`}, func(r Read) {
		t.Errorf("published a read outside every watched folder: %+v", r)
	})
	const key = 0x1234
	w.park(pendingRead{fileKey: key, pid: 9, bytes: 512})
	w.learn(&w.byRunCur, key, `\Device\HarddiskVolume3\Elsewhere\x.txt`)
	w.sweepDeferred(true)
}

func TestParkingIsBounded(t *testing.T) {
	// Reaching the bound means correlation is broken, and the overflow is counted
	// rather than silently discarded.
	w := newTestWatcher(t, []string{`C:\Watched`}, nil)
	for i := 0; i < deferredMax+10; i++ {
		w.park(pendingRead{fileKey: uint64(i)})
	}
	w.rmu.Lock()
	held := w.deferredHeld
	w.rmu.Unlock()
	if held != deferredMax {
		t.Fatalf("parked %d reads, want the bound of %d", held, deferredMax)
	}
	if got := w.dropped.Load(); got != 10 {
		t.Fatalf("dropped counter reports %d, want 10", got)
	}
}

func TestIRPCollisionQuarantinesBothReads(t *testing.T) {
	// A reused IRP address means two operations cannot be told apart. Publishing
	// either could attach one operation's outcome to the other's file, so both go.
	w := newTestWatcher(t, []string{`C:\Watched`}, nil)
	w.pend(0x99, pendingRead{fileKey: 1, pid: 100})
	w.pend(0x99, pendingRead{fileKey: 2, pid: 200})
	if _, ok := w.takePending(0x99); ok {
		t.Fatal("a collided IRP was still resolvable; both sides must be quarantined")
	}
}

func TestLookupFindsNamesInEitherGeneration(t *testing.T) {
	// Rotation must not lose a name a read still needs; the previous generation
	// is consulted on a miss.
	w := newTestWatcher(t, nil, nil)
	w.learn(&w.byRunCur, 0xAA, `\Device\HarddiskVolume3\a.txt`)
	w.rotate()
	if _, ok := w.lookup(0, 0xAA); !ok {
		t.Fatal("a name was lost by one rotation; it must survive into the previous generation")
	}
	w.rotate()
	if _, ok := w.lookup(0, 0xAA); ok {
		t.Fatal("a name survived two rotations; the maps would grow without bound")
	}
}
