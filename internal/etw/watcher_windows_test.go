//go:build windows

package etw

import (
	"encoding/binary"
	"strings"
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

func TestWantedNTMatchesTheBoundVolumeNotADriveLetter(t *testing.T) {
	// Authorization is on the device the folder was bound to. A drive letter is a
	// mutable mapping, so matching on the letter let a letter reassigned to
	// another volume authorise reads the owner never asked for.
	w := New(nil, 0, nil, nil)
	w.roots = []watchRoot{
		{nt: `\device\harddiskvolume1\watched`, display: `C:\Watched`},
		{nt: `\device\harddiskvolume11\stick`, display: `D:\Stick`},
	}
	cases := []struct {
		nt   string
		want string
	}{
		{`\Device\HarddiskVolume1\Watched\a.txt`, `C:\Watched\a.txt`},
		{`\Device\HarddiskVolume1\Watched`, `C:\Watched`},
		{`\Device\HarddiskVolume11\Stick\b.txt`, `D:\Stick\b.txt`},
		// A different volume whose device name merely starts the same way.
		{`\Device\HarddiskVolume111\Watched\a.txt`, ""},
		// The right volume, a folder that is not watched.
		{`\Device\HarddiskVolume1\Elsewhere\a.txt`, ""},
		// A sibling whose name merely starts with the watched root's.
		{`\Device\HarddiskVolume1\WatchedElsewhere\a.txt`, ""},
	}
	for _, c := range cases {
		got, ok := w.wantedNT(c.nt)
		if c.want == "" {
			if ok {
				t.Errorf("wantedNT(%q) matched as %q, want no match", c.nt, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("wantedNT(%q) = %q,%v want %q,true", c.nt, got, ok, c.want)
		}
	}
}

func TestDisplayPathComesFromTheRootThatMatched(t *testing.T) {
	// Rebuilt from the root that matched rather than looked up, so the reported
	// path can never name a volume other than the one the read came from.
	w := New(nil, 0, nil, nil)
	w.roots = []watchRoot{{nt: `\device\harddiskvolume9\photos`, display: `X:\Photos`}}
	got, ok := w.wantedNT(`\Device\HarddiskVolume9\Photos\sub\IMG.jpg`)
	if !ok || got != `X:\Photos\sub\IMG.jpg` {
		t.Fatalf("got %q,%v", got, ok)
	}
}

func TestNoWatchedRootsMatchesNothing(t *testing.T) {
	// A watcher with nothing bound must publish nothing, rather than treating an
	// empty root list as "everything".
	w := New(nil, 0, nil, nil)
	if _, ok := w.wantedNT(`\Device\HarddiskVolume1nything.txt`); ok {
		t.Fatal("an empty root list matched a path; it must match nothing")
	}
}

func newTestWatcher(t *testing.T, keep []string, emit func(Read)) *Watcher {
	t.Helper()
	w := New(keep, 0, emit, nil)
	w.initState()
	w.rmu.Lock()
	for _, k := range w.keep {
		if len(k) > 2 && k[1] == ':' {
			w.roots = append(w.roots, watchRoot{
				nt:      `\device\harddiskvolume3` + strings.ToLower(k[2:]),
				display: k,
			})
		}
	}
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
	// An *unused* name goes after two rotations, or the maps never shrink.
	w.learn(&w.byRunCur, 0xBB, `\Device\HarddiskVolume3\b.txt`)
	w.rotate()
	w.rotate()
	if _, ok := w.lookup(0, 0xBB); ok {
		t.Fatal("an unused name survived two rotations; the maps would grow without bound")
	}
}

func TestAUsedNameSurvivesRotationIndefinitely(t *testing.T) {
	// A file's name is published once, when its handle is created. A handle held
	// open for hours - a database, a log, a mapped library - is never named
	// again, so without promotion the busiest readers on the machine would be
	// exactly the ones ReadWatch stopped being able to name.
	w := newTestWatcher(t, nil, nil)
	const key = 0xC0FFEE
	const want = `\Device\HarddiskVolume3\long-lived.dat`
	w.learn(&w.byRunCur, key, want)
	for i := 0; i < 10; i++ {
		w.rotate()
		name, ok := w.lookup(0, key)
		if !ok {
			t.Fatalf("name lost after %d rotations despite being used between each", i+1)
		}
		if name != want {
			t.Fatalf("name changed to %q", name)
		}
	}
}

func TestPromotionAppliesToFileObjectNamesToo(t *testing.T) {
	w := newTestWatcher(t, nil, nil)
	const obj = 0xABCD
	w.learn(&w.byObjCur, obj, `\Device\HarddiskVolume3\by-object.txt`)
	w.rotate()
	if _, ok := w.lookup(obj, 0); !ok {
		t.Fatal("a FileObject name did not survive one rotation")
	}
	w.rotate()
	if _, ok := w.lookup(obj, 0); !ok {
		t.Fatal("a FileObject name used between rotations was still dropped")
	}
}

func TestADeletedIdentityIsRetiredNotLearned(t *testing.T) {
	// A delete event says this identity has stopped meaning this file. It used to
	// be fed to learn alongside the create events, teaching the map a mapping at
	// the exact moment it became false.
	w := newTestWatcher(t, nil, nil)
	const key = 0xDEAD01
	w.learn(&w.byKeyCur, key, `\Device\HarddiskVolume3\gone.txt`)
	if _, ok := w.lookup(0, key); !ok {
		t.Fatal("setup: the name was not learned")
	}
	w.forget(&w.byKeyCur, &w.byKeyPrev, key)
	if name, ok := w.lookup(0, key); ok {
		t.Fatalf("a deleted identity still resolves to %q", name)
	}
}

func TestRetirementClearsBothGenerations(t *testing.T) {
	// Promotion makes a single-generation delete useless: the next lookup would
	// pull the stale name straight back into the current map.
	w := newTestWatcher(t, nil, nil)
	const obj = 0xBEEF02
	w.learn(&w.byObjCur, obj, `\Device\HarddiskVolume3\closing.txt`)
	w.rotate() // the name is now only in prev
	w.forget(&w.byObjCur, &w.byObjPrev, obj)
	if name, ok := w.lookup(obj, 0); ok {
		t.Fatalf("a retired name came back from the previous generation as %q", name)
	}
}

func TestAReusedFileObjectCannotInheritTheOldName(t *testing.T) {
	// The kernel reuses FILE_OBJECT addresses. Reporting a read of B as a read of
	// A is worse than reporting nothing, so the close has to retire the mapping.
	var got []Read
	w := newTestWatcher(t, []string{`C:\Watched`}, func(r Read) { got = append(got, r) })
	const obj = 0xABBA03

	w.learn(&w.byObjCur, obj, `\Device\HarddiskVolume3\Watched\first.txt`)
	w.forget(&w.byObjCur, &w.byObjPrev, obj) // Cleanup/Close frees the object

	// The same address now belongs to a different file that nothing has named.
	w.park(pendingRead{fileObject: obj, pid: 11, bytes: 8})
	w.sweepDeferred(true)

	for _, r := range got {
		if r.Path == `C:\Watched\first.txt` {
			t.Fatalf("a read of a reused file object was attributed to the closed file: %+v", r)
		}
	}
	if w.neverNamed.Load() != 1 {
		t.Fatalf("the unnameable read should be a counted gap, neverNamed=%d", w.neverNamed.Load())
	}
}

func TestEventTimeUsesTheProviderTimestamp(t *testing.T) {
	// The read's own time, not the moment the callback happened to run.
	want := time.Date(2026, time.August, 17, 23, 24, 26, 751630900, time.UTC)
	ticks := windowsToUnixEpoch100ns + want.UnixNano()/100
	if got := eventTime(ticks); !got.Equal(want) {
		t.Fatalf("eventTime(%d) = %s, want %s", ticks, got, want)
	}
	// A nonsense timestamp yields the zero time, which the pipeline replaces with
	// now rather than reporting a read from 1601.
	if got := eventTime(0); !got.IsZero() {
		t.Fatalf("eventTime(0) = %s, want the zero time", got)
	}
}

func TestParkingStaysBoundedAcrossASweep(t *testing.T) {
	// The sweep detaches the parked set, which reset the count to zero. Callbacks
	// could then fill another whole generation while it ran, and the unresolved
	// set was added back on top without a check - the structure grew by a cap's
	// worth every sweep.
	w := newTestWatcher(t, []string{`C:\Watched`}, nil)
	for i := 0; i < deferredMax; i++ {
		w.park(pendingRead{fileKey: uint64(i + 1)})
	}
	// Nothing can name any of these, so the sweep tries to put them all back.
	w.sweepDeferred(false)
	w.rmu.Lock()
	held := w.deferredHeld
	w.rmu.Unlock()
	if held > deferredMax {
		t.Fatalf("parked set grew to %d across a sweep, cap is %d", held, deferredMax)
	}
}

func TestAStartedReadWhoseCompletionNeverArrivesExpires(t *testing.T) {
	// IRP values are pointers the kernel reuses. An entry whose OperationEnd was
	// lost must not sit there until some later operation's completion consumes it
	// and publishes this read with that operation's status and byte count.
	w := newTestWatcher(t, []string{`C:\Watched`}, nil)
	w.pend(0x1000, pendingRead{fileKey: 1, pid: 5, at: time.Now().UTC().Add(-2 * pendingMaxAge)})
	w.pend(0x2000, pendingRead{fileKey: 2, pid: 5, at: time.Now().UTC()})

	w.expirePending()

	if _, ok := w.takePending(0x1000); ok {
		t.Error("a read older than the maximum age survived; a reused IRP could complete it")
	}
	if _, ok := w.takePending(0x2000); !ok {
		t.Error("a recent read was expired")
	}
	if w.expired.Load() != 1 {
		t.Errorf("expiry counted %d, want 1 — an unresolved read is a gap in the record", w.expired.Load())
	}
}

func TestIRPCollisionsAreCounted(t *testing.T) {
	w := newTestWatcher(t, nil, nil)
	w.pend(0x99, pendingRead{fileKey: 1})
	w.pend(0x99, pendingRead{fileKey: 2})
	if w.collisions.Load() != 1 {
		t.Fatalf("collisions counted %d, want 1 — quarantining silently hides a real loss", w.collisions.Load())
	}
}
