//go:build windows

package etw

import (
	"errors"
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
	// nameMapMax bounds each generation of the name maps. A service runs for
	// hours, not the twelve seconds a probe runs, so names must be retired or the
	// maps grow without limit. Two generations are kept: a name is only dropped
	// after it has survived a full sweep without being needed.
	nameMapMax = 1 << 16
	// pendingReadMax bounds reads awaiting their completion event.
	pendingReadMax = 20000
	// deferredMax bounds reads awaiting a name. Reaching it means correlation is
	// broken, not that a backlog is worth keeping.
	deferredMax = 50000
	// sweepInterval is how often parked reads are retried. Names for handles that
	// predate the session arrive well after the reads do, so this is the primary
	// naming path rather than a fallback: on a qualification run 3,893 of 4,965
	// resolved reads were named by a sweep, not at completion.
	sweepInterval = 2 * time.Second
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
	mu           sync.Mutex
	session      *session
	stop         chan struct{}
	done         chan struct{}
	consumerDone chan struct{}

	// roots are the watched folders, each bound to the volume device it resolved
	// to when monitoring started. Everything else on the machine is decoded and
	// discarded: this provider cannot be filtered by path, so the consumer sees
	// every read and throws away what it did not ask for.
	roots   []watchRoot
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
	drainTimedOut         atomic.Bool
	retired               atomic.Uint64
	unboundRoots          atomic.Uint64
}

// errAlreadyActive guards the one-per-process rule. ETW's callback is a C
// function pointer with no user context that survives the round trip, so a
// second concurrent watcher would silently steal the first one's events.
var errAlreadyActive = errors.New("an ETW watcher is already running in this process")

var (
	active        atomic.Pointer[Watcher]
	eventCallback = syscall.NewCallback(onEvent)
)

// New builds a watcher. keep is the set of folders whose reads should be
// emitted; a read outside all of them is discarded in this process rather than
// sent anywhere.
func New(keep []string, selfPID uint32, emit func(Read), onError func(error)) *Watcher {
	w := &Watcher{selfPID: selfPID, emit: emit, onError: onError}
	w.setKeep(keep)
	return w
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

// bindRoots resolves each configured folder to the volume device behind its
// drive letter. A folder whose letter cannot be resolved is not watched rather
// than watched by name, and is counted so the gap is visible.
func (w *Watcher) bindRoots() {
	var out []watchRoot
	for _, f := range w.keep {
		if len(f) < 2 || f[1] != ':' {
			w.unboundRoots.Add(1)
			continue
		}
		device, ok := deviceForLetter(strings.ToUpper(f[:1]) + ":")
		if !ok {
			w.unboundRoots.Add(1)
			continue
		}
		nt := strings.ToLower(strings.TrimRight(device, `\`) + f[2:])
		out = append(out, watchRoot{nt: nt, display: f})
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

// setKeep records the configured folders as the owner wrote them. The case is
// preserved deliberately: this is now the display form, and matching happens on
// the lowercased device path built from it.
func (w *Watcher) setKeep(folders []string) {
	norm := make([]string, 0, len(folders))
	for _, f := range folders {
		f = strings.TrimRight(strings.TrimSpace(f), `\/`)
		if f != "" {
			norm = append(norm, f)
		}
	}
	w.keep = norm
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
	lost, known := w.sessionLost, w.lostKnown
	w.rmu.Unlock()
	return Counters{
		Dropped:     w.dropped.Load(),
		NeverNamed:  w.neverNamed.Load(),
		SessionLost: uint64(lost),
		LostKnown:   known,
		Observed:    w.observed.Load(),
		Named:       w.named.Load(),
		Published:   w.published.Load(),
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
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	w.running.Store(true)

	consumerDone := make(chan struct{})
	w.consumerDone = consumerDone
	go func() {
		defer close(consumerDone)
		if err := s.openAndProcess(eventCallback); err != nil {
			w.report(err)
		}
	}()

	if err := s.waitConsumerReady(5 * time.Second); err != nil {
		w.running.Store(false)
		active.Store(nil)
		s.Stop()
		<-consumerDone
		w.session = nil
		return err
	}
	// A failed rundown is not fatal: reads on handles opened from here on still
	// resolve. It only costs the names of files that were already open.
	if err := s.requestRundown(); err != nil {
		w.report(err)
	}
	go w.housekeeping(consumerDone)
	return nil
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
	s.Stop()
	<-done
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
				w.drainTimedOut.Store(true)
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
	w.rmu.Lock()
	for k, v := range readd {
		w.deferred[k] = append(w.deferred[k], v...)
		w.deferredHeld += len(v)
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
	// The rundown's value is matched against FileKey, which is what classic
	// FileIo documents it as and what a qualification run confirmed exactly.
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
	w.rmu.Unlock()
}

func (w *Watcher) learn(m *map[uint64]string, id uint64, name string) {
	if id == 0 || name == "" {
		return
	}
	w.rmu.Lock()
	(*m)[id] = name
	w.rmu.Unlock()
}

func (w *Watcher) pend(irp uint64, p pendingRead) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	if _, dup := w.pending[irp]; dup {
		// An IRP already in flight means a reused address. Quarantining both is
		// the only safe answer: publishing either could attach one operation's
		// outcome to the other's file.
		delete(w.pending, irp)
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
	w := active.Load()
	if w == nil {
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
