//go:build windows

package etw

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Read is one completed, successful, non-empty file read attributed to a
// process. Nothing is emitted until OperationEnd has confirmed all three: a
// request that failed or returned no bytes is not a read of the file.
type Read struct {
	Path  string
	PID   uint32
	TID   uint32
	Bytes uint64
	Time  time.Time
}

// Counters are the numbers a user is entitled to see. Every one of them counts
// something that was *not* delivered, because a monitor that silently drops is
// worse than one that says it dropped.
type Counters struct {
	Dropped     uint64 // the consumer could not keep up
	NeverNamed  uint64 // a read whose file nothing ever named
	SessionLost uint64 // the session itself lost events
	LostKnown   bool
	// Observed and Published are not losses; they are what distinguishes "nothing
	// was read" from "reads are arriving and something downstream is eating
	// them". Without both, a broken filter and a quiet machine look identical.
	Observed  uint64 // read events decoded, machine-wide
	Named     uint64 // of those, resolved to a path
	Published uint64 // of those, inside a watched folder and handed on
	// The remaining ways a read can fail to reach the log, kept apart because
	// they have different causes and different fixes. Collapsing them into one
	// number makes a broken correlation and a busy machine look the same.
	BuffersLost   uint64 // real-time buffers the session lost
	Collisions    uint64 // reused IRP values, both sides quarantined
	Crowded       uint64 // one file's reads beyond its share of the parking queue
	NamesRejected uint64 // names the bounded map could not admit
	Expired       uint64 // started reads whose completion never arrived
	UnboundRoots  uint64 // watched folders whose volume could not be resolved
	// SnapshotNames is how many already-open files the startup snapshot named;
	// SnapshotStale how many it discarded as already closed; SnapshotFailed
	// whether it could not be taken at all, which is a degraded start rather than
	// a failure to monitor.
	SnapshotNames  uint64
	SnapshotStale  uint64
	SnapshotFailed bool
	DrainTimeout   bool // teardown gave up waiting for the consumer
}

const windowsToUnixEpoch100ns int64 = 116444736000000000

// eventTime converts the FILETIME-form timestamp ProcessTrace places in
// EVENT_HEADER.TimeStamp. The consumer does not set
// PROCESS_TRACE_MODE_RAW_TIMESTAMP, so this is 100ns ticks since 1601 rather
// than raw QPC counts.
//
// This is the time the read happened. Stamping time.Now() in the callback
// instead recorded when the event was *delivered*, which for anything the
// provider buffers - and for everything the teardown rundown carries - is a
// different and later moment.
func eventTime(ticks int64) time.Time {
	if ticks <= windowsToUnixEpoch100ns {
		return time.Time{}
	}
	return time.Unix(0, (ticks-windowsToUnixEpoch100ns)*100).UTC()
}

const (
	// nameMapMax bounds each generation of the name maps. 1<<18, not 1<<16: the
	// startup snapshot alone names ~116,000 files on this host, so a smaller
	// bound would reject most of it at every start and the bound would be
	// enforced by throwing away the coverage it was built to provide. A service runs for
	// hours, not the twelve seconds a probe runs, so names must be retired or the
	// maps grow without limit. Two generations are kept: a name is only dropped
	// after it has survived a full sweep without being needed.
	nameMapMax = 1 << 18
	// pendingReadMax bounds reads awaiting their completion event.
	pendingReadMax = 20000
	// deferredMax bounds reads awaiting a name, and deferredPerIdentity bounds how
	// many any one file may contribute.
	//
	// The per-identity cap is the important one. A machine at rest still issues
	// tens of thousands of reads a second, nearly all of them on handles opened
	// before this session existed and so unnameable until the rundown answers. A
	// single first-come-first-served queue is emptied by whichever file is busiest
	// in the first fraction of a second, and the folder the owner actually asked
	// about never gets a slot. Measured here: 620,638 reads observed in seven
	// seconds, 50,000 parked, 570,248 dropped, and the watched file among the
	// dropped. Bounding each identity separately keeps one noisy file from
	// crowding out every quiet one.
	//
	// 256 rather than a handful: at 16 a live run reported only 16 of the 240
	// reads it made of the watched file, because the name for a pre-existing
	// handle does not arrive until the session stops and every read until then
	// has to wait in the queue.
	deferredMax         = 50000
	deferredPerIdentity = 256
	// sweepInterval is how often parked reads are retried. Names for handles that
	// predate the session arrive well after the reads do, so this is the primary
	// naming path rather than a fallback: on a qualification run 3,893 of 4,965
	// resolved reads were named by a sweep, not at completion.
	sweepInterval = 2 * time.Second
	// pendingMaxAge is how long a started read waits for its completion. IRP
	// values are pointers the kernel reuses, so an entry whose OperationEnd was
	// lost must not sit there until some later operation's completion consumes
	// it and publishes this read with that operation's status and byte count.
	pendingMaxAge = 60 * time.Second
	// drainTimeout bounds the wait for ProcessTrace to return at teardown.
	// Microsoft documents that it can take seconds and may still be delivering
	// queued events, so this is generous rather than tight.
	drainTimeout = 30 * time.Second
	// The size bound is checked on every sweep rather than on a slow timer of its
	// own. A minute is a long time at this event rate: the maps could take on
	// millions of entries between checks, which is not a bound in any useful
	// sense.
)

// pendingRead is a read that has started and not yet been told whether it
// worked.
type pendingRead struct {
	path       string // empty when the name had not arrived at start
	fileObject uint64
	fileKey    uint64
	bytes      uint64
	pid        uint32
	tid        uint32
	at         time.Time
}

// Watcher owns one ETW session and turns its stream into Reads. Only one may be
// active in a process: ETW's callback is a C function pointer with no user
// context that survives the round trip, so the active watcher is found through a
// package-level pointer.
type Watcher struct {
	mu      sync.Mutex
	session *session
	// sessionForDrain survives session being cleared at Stop, so housekeeping can
	// still close the consumer if the drain runs out of patience.
	sessionForDrain *session
	stop            chan struct{}
	done            chan struct{}
	consumerDone    chan struct{}

	// roots are the watched folders, each bound to the volume device it resolved
	// to when monitoring started. Everything else on the machine is decoded and
	// discarded: this provider cannot be filtered by path, so the consumer sees
	// every read and throws away what it did not ask for.
	roots   []watchRoot
	bound   []BoundRoot
	keep    []string
	selfPID uint32
	emit    func(Read)
	onError func(error)

	rmu sync.Mutex
	// Name maps in two generations. cur takes new entries; prev is consulted on a
	// miss and dropped whole when cur is rotated in.
	byKeyCur, byKeyPrev   map[uint64]string
	byObjCur, byObjPrev   map[uint64]string
	byRunCur, byRunPrev   map[uint64]string
	pending               map[uint64]pendingRead
	deferred              map[uint64][]pendingRead
	deferredHeld          int
	dropped               atomic.Uint64
	neverNamed            atomic.Uint64
	observed              atomic.Uint64
	named                 atomic.Uint64
	published             atomic.Uint64
	sessionLost, lostBufs uint32
	lostKnown             bool
	running               atomic.Bool
	// token identifies this watcher on every record ETW delivers to it, and
	// accepting says whether it still wants them. The token is the address of
	// tokenCell, pinned for the consumer's life, so it is unique and stable.
	token          uintptr
	tokenCell      *uint64
	pin            runtime.Pinner
	accepting      atomic.Bool
	drainTimedOut  atomic.Bool
	retired        atomic.Uint64
	unboundRoots   atomic.Uint64
	collisions     atomic.Uint64
	expired        atomic.Uint64
	crowded        atomic.Uint64
	namesRejected  atomic.Uint64
	snapshotNames  atomic.Uint64
	snapshotStale  atomic.Uint64
	snapshotFailed atomic.Bool
	initialised    atomic.Bool
	// retiredDuringInit records identities the main session saw closed or deleted
	// while the startup snapshot was being collected, so a name that was already
	// stale when it arrived is never merged. Dropped once initialisation ends.
	retiredDuringInit map[uint64]bool
}

// errAlreadyActive guards the one-session-at-a-time rule. Records are routed by
// their own token, so a second watcher could not steal the first one's events
// even if it existed; this exists because the session name is fixed and two
// watchers would fight over the same logger.
var errAlreadyActive = errors.New("an ETW watcher is already running in this process")

// Consumers are found by the token ETW carries on every record, not by a global
// pointer to whichever watcher is current.
//
// EVENT_TRACE_LOGFILEW.Context is copied into EVENT_RECORD.UserContext, so each
// consumer can be identified from the record itself. The earlier global was
// wrong on both counts: the comment claimed no per-consumer context survives the
// round trip, which is untrue, and a slot released while an old consumer was
// still delivering let one session's records enter a later watcher as if they
// were its own.
var (
	consumers     sync.Map // token -> *Watcher
	nextConsumer  atomic.Uint64
	eventCallback = syscall.NewCallback(onEvent)
	// active only enforces the one-session-at-a-time rule; it is never used to
	// route a record.
	active atomic.Pointer[Watcher]
)

// New builds a watcher. keep is the set of folders whose reads should be
// emitted; a read outside all of them is discarded in this process rather than
// sent anywhere.
// New builds a watcher over roots the caller has already bound to a volume.
func New(roots []BoundRoot, selfPID uint32, emit func(Read), onError func(error)) *Watcher {
	w := &Watcher{selfPID: selfPID, emit: emit, onError: onError, bound: roots}
	for _, r := range roots {
		w.keep = append(w.keep, r.Display)
	}
	return w
}

// RootsFromPaths is for callers that have only paths - the live tests, and
// nothing in the service. It resolves each drive letter once, here, so that the
// watcher itself never does.
func RootsFromPaths(paths []string) []BoundRoot {
	out := make([]BoundRoot, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimRight(strings.TrimSpace(p), `\/`)
		if len(p) < 2 || p[1] != ':' {
			continue
		}
		device, ok := deviceForLetter(strings.ToUpper(p[:1]) + ":")
		if !ok {
			continue
		}
		within := ""
		if len(p) > 2 {
			within = p[2:]
		}
		out = append(out, BoundRoot{Device: device, Within: within, Display: p})
	}
	return out
}

// watchRoot is one watched folder, held as the NT device path the provider
// actually reports and the drive-letter form the owner recognises.
//
// Matching is done on the NT form on purpose. Drive letters are a mutable
// mapping: converting every event to a letter and comparing text there meant a
// letter reassigned to a different volume could authorise reads from that new
// volume under the old watched root, and a lookup that hit a stale entry never
// even triggered a refresh. The device path is what the folder was bound to, so
// it cannot drift; the letter is carried alongside purely so the owner sees the
// path they typed.
type watchRoot struct {
	nt      string // \Device\HarddiskVolumeN\Folder, lowercased
	display string // D:\Folder, as configured
}

// BoundRoot is a watched folder as the binder proved it: the volume device it
// actually sits on, the path within that volume, and the form the owner
// recognises. The watcher never resolves a drive letter itself - the letter is a
// mutable mapping, and re-resolving it at start would reopen the window where a
// reassignment between binding and startup authorises a different volume.
type BoundRoot struct {
	Device  string // \Device\HarddiskVolumeN, as the provider names it
	Within  string // \Folder, the path inside that volume
	Display string // D:\Folder, as the owner wrote it
}

// bindRoots turns the caller's proven roots into the matching form. A root with
// no device is not watched rather than watched by name, and is counted so the
// gap is visible.
func (w *Watcher) bindRoots() {
	var out []watchRoot
	for _, r := range w.bound {
		if r.Device == "" || r.Display == "" {
			w.unboundRoots.Add(1)
			continue
		}
		nt := strings.ToLower(strings.TrimRight(r.Device, `\`) + r.Within)
		out = append(out, watchRoot{nt: nt, display: r.Display})
	}
	w.rmu.Lock()
	w.roots = out
	w.rmu.Unlock()
}

// wantedNT matches a provider path against the bound roots and returns the
// owner-facing path. The display form is rebuilt from the root that matched
// rather than looked up, so it can never name a volume other than the one the
// read actually came from.
func (w *Watcher) wantedNT(ntPath string) (string, bool) {
	lower := strings.ToLower(ntPath)
	w.rmu.Lock()
	roots := w.roots
	w.rmu.Unlock()
	for _, r := range roots {
		if lower == r.nt {
			return r.display, true
		}
		if strings.HasPrefix(lower, r.nt+`\`) {
			return r.display + ntPath[len(r.nt):], true
		}
	}
	return "", false
}

// initState resets every correlation map. Separate from Start so the
// correlation logic can be exercised without opening a session - the parking
// and sweep path is the load-bearing part of this design and untested code
// there would be a false green.
func (w *Watcher) initState() {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	w.byKeyCur = make(map[uint64]string, 1<<12)
	w.byObjCur = make(map[uint64]string, 1<<12)
	w.byRunCur = make(map[uint64]string, 1<<12)
	w.byKeyPrev = map[uint64]string{}
	w.byObjPrev = map[uint64]string{}
	w.byRunPrev = map[uint64]string{}
	w.pending = make(map[uint64]pendingRead, 1<<12)
	w.deferred = make(map[uint64][]pendingRead)
	w.deferredHeld = 0
	w.dropped.Store(0)
	w.neverNamed.Store(0)
	w.observed.Store(0)
	w.named.Store(0)
	w.published.Store(0)
}

func (w *Watcher) Running() bool { return w.running.Load() }

func (w *Watcher) Counters() Counters {
	w.rmu.Lock()
	lost, bufs, known := w.sessionLost, w.lostBufs, w.lostKnown
	w.rmu.Unlock()
	return Counters{
		Dropped:        w.dropped.Load(),
		NeverNamed:     w.neverNamed.Load(),
		SessionLost:    uint64(lost),
		LostKnown:      known,
		Observed:       w.observed.Load(),
		Named:          w.named.Load(),
		Published:      w.published.Load(),
		BuffersLost:    uint64(bufs),
		Collisions:     w.collisions.Load(),
		Crowded:        w.crowded.Load(),
		NamesRejected:  w.namesRejected.Load(),
		Expired:        w.expired.Load(),
		UnboundRoots:   w.unboundRoots.Load(),
		SnapshotNames:  w.snapshotNames.Load(),
		SnapshotStale:  w.snapshotStale.Load(),
		SnapshotFailed: w.snapshotFailed.Load(),
		DrainTimeout:   w.drainTimedOut.Load(),
	}
}

// Start brings up the session and blocks only until the consumer is attached and
// the rundown has been asked for. Everything after that runs on its own
// goroutines.
func (w *Watcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.session != nil {
		return nil
	}

	w.initState()
	w.bindRoots()
	w.retiredDuringInit = make(map[uint64]bool, 1<<12)

	// Claimed before the session is created, and by compare-and-swap rather than
	// a check followed by a store: two watchers sharing one callback would each
	// see only some of the stream, and the check-then-store form leaves a window
	// where both pass.
	if !active.CompareAndSwap(nil, w) {
		return errAlreadyActive
	}

	s, err := startSession()
	if err != nil {
		active.Store(nil)
		return err
	}
	w.session = s
	w.sessionForDrain = s
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	w.running.Store(true)

	// The token is the address of a pinned allocation this watcher owns, so it is
	// unique for as long as the consumer lives and cannot be confused with any
	// other. Windows copies it onto every record as UserContext.
	w.tokenCell = new(uint64)
	*w.tokenCell = nextConsumer.Add(1)
	w.pin.Pin(w.tokenCell)
	w.token = uintptr(unsafe.Pointer(w.tokenCell))
	consumers.Store(w.token, w)
	w.accepting.Store(true)

	consumerDone := make(chan struct{})
	w.consumerDone = consumerDone
	go func() {
		defer close(consumerDone)
		if err := s.openAndProcess(eventCallback, unsafe.Pointer(w.tokenCell)); err != nil {
			w.report(err)
		}
	}()

	if err := s.waitConsumerReady(5 * time.Second); err != nil {
		w.running.Store(false)
		w.accepting.Store(false)
		active.Store(nil)
		_ = s.Stop()
		<-consumerDone
		consumers.Delete(w.token)
		w.pin.Unpin()
		w.session = nil
		return err
	}
	// A failed rundown is not fatal: reads on handles opened from here on still
	// resolve. It only costs the names of files that were already open.
	if err := s.requestRundown(); err != nil {
		w.report(err)
	}

	// The startup filename snapshot, before a single read is enabled. Reads on
	// handles that predate this session cannot be named from the session's own
	// stream until it stops, so they are named here instead - from a second,
	// short-lived logger whose teardown enumerates every open file.
	//
	// Any identity whose handle closed or was deleted while the snapshot was
	// being taken is discarded rather than merged: the main session has been
	// watching lifetime events throughout, and a name that was already stale when
	// it arrived is exactly how a read of one file gets attributed to another.
	if names, err := takeSnapshot(); err != nil {
		w.snapshotFailed.Store(true)
		w.report(fmt.Errorf("startup filename snapshot unavailable, reads on handles opened before now may be unnamed until monitoring stops: %w", err))
	} else {
		w.mergeSnapshot(names)
	}

	if err := s.enableReads(); err != nil {
		w.running.Store(false)
		w.accepting.Store(false)
		active.Store(nil)
		_ = s.Stop()
		<-consumerDone
		consumers.Delete(w.token)
		w.pin.Unpin()
		w.session = nil
		return err
	}
	w.initialised.Store(true)
	go w.housekeeping(consumerDone)
	return nil
}

// mergeSnapshot folds the startup names in, skipping any identity the main
// session saw close or be deleted while the snapshot was being collected.
func (w *Watcher) mergeSnapshot(names map[uint64]string) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	kept := 0
	for key, name := range names {
		if w.retiredDuringInit[key] {
			w.snapshotStale.Add(1)
			continue
		}
		if _, already := w.byKeyCur[key]; already {
			// The live stream already named it, and the live stream is newer.
			continue
		}
		before := len(w.byRunCur)
		w.learnLocked(&w.byRunCur, key, name)
		if len(w.byRunCur) > before {
			kept++
		}
	}
	w.snapshotNames.Store(uint64(kept))
	w.retiredDuringInit = nil
}

// Stop tears down the session and waits for the consumer to leave ProcessTrace.
// Nothing ETW-related may outlive a Stop.
func (w *Watcher) Stop() {
	w.mu.Lock()
	s := w.session
	if s == nil {
		w.mu.Unlock()
		return
	}
	w.session = nil
	stop, done := w.stop, w.done
	w.mu.Unlock()

	// Record what the session lost before stopping it: the query needs a live
	// handle, and after Stop there is nothing left to ask.
	lost, bufs, known := s.Lost()
	w.rmu.Lock()
	w.sessionLost, w.lostBufs, w.lostKnown = lost, bufs, known
	w.rmu.Unlock()

	// Order matters more here than anywhere else in the package.
	//
	// Stopping the session is what provokes the teardown rundown, and that
	// rundown is the only thing that names a handle opened before the session
	// started - the whole reason unresolved reads are parked. Clearing the
	// callback's global before stopping the session therefore threw away exactly
	// the events the design exists to collect: onEvent discards everything while
	// active is nil. The callback stays live until the consumer has actually left
	// ProcessTrace.
	//
	// It also has to stay claimed that long. Releasing the slot while the old
	// consumer is still delivering would let a second watcher claim it and
	// receive the first session's events as if they were its own.
	w.running.Store(false)
	close(stop)
	if err := s.Stop(); err != nil {
		// A session that outlives the process is the one thing this package must
		// never leave behind, so a stop that did not take is reported rather than
		// swallowed. The next start clears an orphan by name, but nobody should
		// have to find out that way.
		w.report(err)
	}
	<-done
	// The consumer is only retired once it has actually left ProcessTrace. If the
	// drain ran out of patience, housekeeping has already asked it to close, and
	// this waits for that to take effect rather than releasing the token while
	// records may still arrive. Until then the watcher stops accepting, so late
	// records are dropped by their own consumer rather than handed to another.
	w.accepting.Store(false)
	select {
	case <-w.consumerDone:
	case <-time.After(drainTimeout):
	}
	consumers.Delete(w.token)
	w.pin.Unpin()
	active.Store(nil)
}

// housekeeping runs the two periodic jobs: retrying reads that have no name yet,
// and retiring names so the maps stay bounded.
func (w *Watcher) housekeeping(consumerDone chan struct{}) {
	defer close(w.done)
	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()
	for {
		select {
		case <-sweep.C:
			w.sweepDeferred(false)
			w.expirePending()
			w.rotateNames()
		case <-w.stop:
			// The stream is still being drained, and the rundown a system logger
			// emits at teardown is exactly what names the oldest handles. So the
			// final sweep waits for the consumer to leave ProcessTrace rather than
			// racing it. Microsoft documents that ProcessTrace can take seconds to
			// return and may still be delivering queued events, so the wait is
			// generous; a wait that expires is counted rather than passed over,
			// because everything still parked at that point is a real gap.
			select {
			case <-consumerDone:
			case <-time.After(drainTimeout):
				// Out of patience. Ask the consumer to close rather than simply
				// walking away from it: CloseTrace may be called while
				// ProcessTrace is still running, and it stops further delivery
				// after draining what is already queued. Walking away left a live
				// consumer whose records could reach a later watcher.
				w.drainTimedOut.Store(true)
				w.mu.Lock()
				s := w.sessionForDrain
				w.mu.Unlock()
				if s != nil {
					s.closeConsumer()
				}
				select {
				case <-consumerDone:
				case <-time.After(drainTimeout):
				}
			}
			w.sweepDeferred(true)
			return
		}
	}
}

// sweepDeferred retries every parked read. final says whether this is the last
// chance: only then is an unnamed read counted as never named, because before
// that its name may still be coming.
func (w *Watcher) sweepDeferred(final bool) {
	w.rmu.Lock()
	parked := w.deferred
	w.deferred = make(map[uint64][]pendingRead)
	w.deferredHeld = 0
	w.rmu.Unlock()

	var readd map[uint64][]pendingRead
	for key, reads := range parked {
		for _, p := range reads {
			name, ok := w.lookup(p.fileObject, key)
			if !ok {
				if final {
					w.neverNamed.Add(1)
					continue
				}
				if readd == nil {
					readd = make(map[uint64][]pendingRead)
				}
				readd[key] = append(readd[key], p)
				continue
			}
			w.publish(name, p)
		}
	}
	if readd == nil {
		return
	}
	// The cap has to hold across the merge, not just on insert. Detaching the
	// parked set reset the count to zero, so callbacks could fill another whole
	// generation while the sweep ran and the unresolved set was then added back
	// on top of it without a check - the structure grew by a cap's worth every
	// sweep. What does not fit is dropped and counted, never quietly kept.
	w.rmu.Lock()
	for _, v := range readd {
		for _, p := range v {
			w.parkLocked(p)
		}
	}
	w.rmu.Unlock()
}

// rotateNames drops the older generation and starts a new one. A name is only
// discarded after surviving a full interval unused by a rotation, which keeps
// the maps bounded without throwing away a mapping a read still needs.
func (w *Watcher) rotateNames() {
	w.rmu.Lock()
	over := len(w.byKeyCur) >= nameMapMax || len(w.byObjCur) >= nameMapMax || len(w.byRunCur) >= nameMapMax
	w.rmu.Unlock()
	if over {
		w.rotate()
	}
}

func (w *Watcher) rotate() {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	w.rotateLocked()
}

func (w *Watcher) rotateLocked() {
	w.byKeyPrev, w.byKeyCur = w.byKeyCur, make(map[uint64]string, 1<<12)
	w.byObjPrev, w.byObjCur = w.byObjCur, make(map[uint64]string, 1<<12)
	w.byRunPrev, w.byRunCur = w.byRunCur, make(map[uint64]string, 1<<12)
}

// lookup finds a name in either generation, and promotes a hit in the older one
// back into the current one.
//
// The promotion is the point. A file's name is published once, when its handle
// is created; a handle held open for hours - a database, a log, a mapped
// library - is never named again. Without promotion, two rotations would drop
// that name and every later read of it would go unattributed, so the busiest
// readers on the machine would be exactly the ones ReadWatch stopped naming.
func (w *Watcher) lookup(obj, key uint64) (string, bool) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	if n, ok := w.byObjCur[obj]; ok {
		return n, true
	}
	if n, ok := w.byObjPrev[obj]; ok {
		w.byObjCur[obj] = n
		return n, true
	}
	// The rundown's value is matched against FileKey only. Classic FileIo names
	// its field "FileObject", but Microsoft's own instrumentation notes say that
	// field is a file *key*; the two are both pointer-shaped and are not
	// interchangeable. A second arm matching it against a read's FileObject was
	// tried and removed: the live teardown test publishes all 240 reads of a
	// pre-opened handle without it, so it bought nothing, and Cleanup/Close
	// retires only byObj - so a stale byRun entry at a reused file-object address
	// could have outlived the very event that makes the address reusable and named
	// the wrong file.
	if n, ok := w.byKeyCur[key]; ok {
		return n, true
	}
	if n, ok := w.byRunCur[key]; ok {
		return n, true
	}
	if n, ok := w.byKeyPrev[key]; ok {
		w.byKeyCur[key] = n
		return n, true
	}
	if n, ok := w.byRunPrev[key]; ok {
		w.byRunCur[key] = n
		return n, true
	}
	return "", false
}

// forget retires an identity from both generations. Promotion makes a
// single-generation delete useless: the next lookup would pull the stale name
// straight back into the current map.
func (w *Watcher) forget(cur, prev *map[uint64]string, id uint64) {
	if id == 0 {
		return
	}
	w.rmu.Lock()
	delete(*cur, id)
	delete(*prev, id)
	if w.retiredDuringInit != nil {
		w.retiredDuringInit[id] = true
	}
	w.rmu.Unlock()
}

func (w *Watcher) learn(m *map[uint64]string, id uint64, name string) {
	if id == 0 || name == "" {
		return
	}
	w.rmu.Lock()
	w.learnLocked(m, id, name)
	w.rmu.Unlock()
}

// learnLocked admits a name only if the current generation has room. Rotating
// after an overshoot is not a bound: a startup snapshot of 116,000 names walked
// straight past a stated maximum of 65,536 before anything was rotated. When the
// generation is full it is rotated here, at the moment of insertion, and a name
// that still cannot be admitted is counted rather than quietly kept.
func (w *Watcher) learnLocked(m *map[uint64]string, id uint64, name string) {
	if len(*m) >= nameMapMax {
		w.rotateLocked()
	}
	if len(*m) >= nameMapMax {
		w.namesRejected.Add(1)
		return
	}
	(*m)[id] = name
}

func (w *Watcher) pend(irp uint64, p pendingRead) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	if _, dup := w.pending[irp]; dup {
		// An IRP already in flight means a reused address. Quarantining both is
		// the only safe answer: publishing either could attach one operation's
		// outcome to the other's file.
		delete(w.pending, irp)
		w.collisions.Add(1)
		return
	}
	if len(w.pending) >= pendingReadMax {
		// Drop the whole generation rather than grow without bound or evict
		// arbitrarily, and count it: a run that hits this is visibly degraded.
		w.dropped.Add(uint64(len(w.pending)))
		w.pending = make(map[uint64]pendingRead, 1<<12)
	}
	w.pending[irp] = p
}

// expirePending drops started reads whose completion never arrived. Each one is
// counted: a read that started and was never resolved is a gap in the record,
// and leaving it in the map turns it into a future misattribution instead.
func (w *Watcher) expirePending() {
	cutoff := time.Now().UTC().Add(-pendingMaxAge)
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for irp, p := range w.pending {
		if p.at.IsZero() || p.at.Before(cutoff) {
			delete(w.pending, irp)
			w.expired.Add(1)
		}
	}
}

func (w *Watcher) takePending(irp uint64) (pendingRead, bool) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	p, ok := w.pending[irp]
	if ok {
		delete(w.pending, irp)
	}
	return p, ok
}

func (w *Watcher) park(p pendingRead) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	w.parkLocked(p)
}

func (w *Watcher) parkLocked(p pendingRead) {
	if len(w.deferred[p.fileKey]) >= deferredPerIdentity {
		// This file has already contributed as much as it may. Its later reads are
		// lost, and counted, but they cannot take the slot of a file nothing has
		// heard from yet.
		w.crowded.Add(1)
		return
	}
	if w.deferredHeld >= deferredMax {
		w.dropped.Add(1)
		return
	}
	w.deferred[p.fileKey] = append(w.deferred[p.fileKey], p)
	w.deferredHeld++
}

// publish converts an NT device path to a drive-letter path and hands it on if
// it falls inside a watched folder.
func (w *Watcher) publish(ntPath string, p pendingRead) {
	if p.pid == w.selfPID {
		return
	}
	w.named.Add(1)
	display, ok := w.wantedNT(ntPath)
	if !ok {
		return
	}
	w.published.Add(1)
	if w.emit != nil {
		w.emit(Read{Path: display, PID: p.pid, TID: p.tid, Bytes: p.bytes, Time: p.at})
	}
}

func (w *Watcher) report(err error) {
	if err != nil && w.onError != nil {
		w.onError(err)
	}
}

// onEvent is ETW's callback. It runs on ETW's own thread, so it copies what it
// needs out of the record and does no blocking work.
func onEvent(rec *EVENT_RECORD) uintptr {
	if rec.UserContext == nil {
		return 0
	}
	v, ok := consumers.Load(uintptr(rec.UserContext))
	if !ok {
		// The consumer this record belongs to has been retired. Dropping it is
		// right; handing it to whichever watcher is current would attribute one
		// session's reads to another's configuration.
		return 0
	}
	w := v.(*Watcher)
	if !w.accepting.Load() {
		return 0
	}
	provider := rec.EventHeader.ProviderId
	id := rec.EventHeader.EventDescriptor.Id
	opcode := rec.EventHeader.EventDescriptor.Opcode

	if provider.equals(fileIoGUID) {
		switch opcode {
		case fileIoNameType, fileIoFileCreate, fileIoFileRundown:
			if obj, name, err := decodeFileIoName(payload(rec)); err == nil {
				w.learn(&w.byRunCur, obj, name)
			}
		case fileIoFileDelete:
			// A delete event says this identity has stopped meaning this file. It
			// was being fed to learn along with the create events, which taught the
			// map a mapping at the exact moment it became false.
			if obj, _, err := decodeFileIoName(payload(rec)); err == nil {
				w.forget(&w.byRunCur, &w.byRunPrev, obj)
			}
		}
		return 0
	}
	if !provider.equals(kernelFileProvider) {
		return 0
	}

	switch id {
	case evNameCreate:
		if n, err := decodeName(payload(rec)); err == nil {
			w.learn(&w.byKeyCur, n.FileKey, n.Name)
		}
	case evNameDelete:
		if n, err := decodeName(payload(rec)); err == nil {
			w.forget(&w.byKeyCur, &w.byKeyPrev, n.FileKey)
		}
	case evCreate:
		if c, err := decodeCreate(payload(rec)); err == nil {
			w.learn(&w.byObjCur, c.FileObject, c.Name)
		}
	case evCleanup, evClose:
		// The file object is being freed, and the kernel reuses those addresses.
		// Keeping the mapping meant a later object at the same address could be
		// named as this file - a read of B reported as a read of A, which is worse
		// than reporting nothing.
		//
		// Only the FileObject is retired. FileKey identifies the stream, which
		// outlives any one handle and may still be open elsewhere; classic
		// FileDelete is what retires that. A read already in flight keeps whatever
		// path it copied at start, and one that never learned a name becomes a
		// counted gap rather than a guess.
		if c, err := decodeClose(payload(rec)); err == nil {
			w.forget(&w.byObjCur, &w.byObjPrev, c.FileObject)
			w.retired.Add(1)
		}
	case evRead:
		r, err := decodeRead(payload(rec))
		if err != nil {
			return 0
		}
		w.observed.Add(1)
		p := pendingRead{
			fileObject: r.FileObject,
			fileKey:    r.FileKey,
			pid:        rec.EventHeader.ProcessId,
			tid:        r.IssuingThreadID,
			at:         eventTime(rec.EventHeader.TimeStamp),
		}
		if name, ok := w.lookup(r.FileObject, r.FileKey); ok {
			p.path = name
		}
		w.pend(r.Irp, p)
	case evOperationEnd:
		oe, err := decodeOpEnd(payload(rec))
		if err != nil {
			return 0
		}
		p, ok := w.takePending(oe.Irp)
		if !ok {
			// A completion for something that was not a read this watcher started:
			// writes and every other file operation land here. Not loss.
			return 0
		}
		if oe.Status != 0 || oe.ExtraInformation == 0 {
			// Failed, or transferred nothing. Neither is a read of the file.
			return 0
		}
		p.bytes = oe.ExtraInformation
		if p.path == "" {
			// Second chance: the name may have arrived between start and completion.
			if name, found := w.lookup(p.fileObject, p.fileKey); found {
				p.path = name
			}
		}
		if p.path == "" {
			// Park rather than drop. For a handle opened before the session the only
			// thing that can name it is the rundown, and the rundown answers late.
			w.park(p)
			return 0
		}
		w.publish(p.path, p)
	}
	return 0
}

// deviceForLetter resolves a drive letter to the volume device the provider
// names in its events. Called once per watched folder when monitoring starts,
// so the binding is fixed for the session: a letter reassigned afterwards
// cannot silently move a watched root onto a different volume.
func deviceForLetter(letter string) (string, bool) {
	buf := make([]uint16, 1024)
	n, _, _ := procQueryDosDeviceW.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(letter))),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if n == 0 {
		return "", false
	}
	device := syscall.UTF16ToString(buf)
	if device == "" {
		return "", false
	}
	return device, true
}

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procQueryDosDeviceW = kernel32.NewProc("QueryDosDeviceW")
)
