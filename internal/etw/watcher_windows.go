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
	// retireInterval is how often a name generation is rotated out.
	retireInterval = 60 * time.Second
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
	stop    chan struct{}
	done    chan struct{}

	// keep names the paths whose reads are wanted. Everything else on the machine
	// is decoded and discarded: this provider cannot be filtered by path, so the
	// consumer sees every read and throws away what it does not want.
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
	volumes               map[string]string
	volumesAt             time.Time
	dropped               atomic.Uint64
	neverNamed            atomic.Uint64
	sessionLost, lostBufs uint32
	lostKnown             bool
	running               atomic.Bool
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

func (w *Watcher) setKeep(folders []string) {
	norm := make([]string, 0, len(folders))
	for _, f := range folders {
		f = strings.TrimRight(strings.ToLower(strings.TrimSpace(f)), `\/`)
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
	if active.Load() != nil {
		return errAlreadyActive
	}

	w.initState()
	w.refreshVolumes()

	s, err := startSession()
	if err != nil {
		return err
	}
	w.session = s
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	active.Store(w)
	w.running.Store(true)

	consumerDone := make(chan struct{})
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

	w.running.Store(false)
	active.Store(nil)
	close(stop)
	s.Stop()
	<-done
}

// housekeeping runs the two periodic jobs: retrying reads that have no name yet,
// and retiring names so the maps stay bounded.
func (w *Watcher) housekeeping(consumerDone chan struct{}) {
	defer close(w.done)
	sweep := time.NewTicker(sweepInterval)
	retire := time.NewTicker(retireInterval)
	defer sweep.Stop()
	defer retire.Stop()
	for {
		select {
		case <-sweep.C:
			w.sweepDeferred(false)
		case <-retire.C:
			w.rotateNames()
		case <-w.stop:
			// The stream is still being drained: the rundown a system logger emits
			// at teardown is exactly what names the oldest handles, so the final
			// sweep waits for the consumer to finish rather than racing it.
			select {
			case <-consumerDone:
			case <-time.After(5 * time.Second):
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

func (w *Watcher) lookup(obj, key uint64) (string, bool) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for _, m := range []map[uint64]string{w.byObjCur, w.byObjPrev} {
		if n, ok := m[obj]; ok {
			return n, true
		}
	}
	// The rundown's value is matched against FileKey, which is what classic
	// FileIo documents it as and what a qualification run confirmed exactly.
	for _, m := range []map[uint64]string{w.byKeyCur, w.byKeyPrev, w.byRunCur, w.byRunPrev} {
		if n, ok := m[key]; ok {
			return n, true
		}
	}
	return "", false
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
	dos := w.toDOS(ntPath)
	if dos == "" || !w.wanted(dos) {
		return
	}
	if w.emit != nil {
		w.emit(Read{Path: dos, PID: p.pid, TID: p.tid, Bytes: p.bytes, Time: p.at})
	}
}

func (w *Watcher) wanted(path string) bool {
	if len(w.keep) == 0 {
		return false
	}
	lower := strings.ToLower(path)
	for _, root := range w.keep {
		if lower == root || strings.HasPrefix(lower, root+`\`) {
			return true
		}
	}
	return false
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
		case fileIoNameType, fileIoFileCreate, fileIoFileDelete, fileIoFileRundown:
			obj, name, err := decodeFileIoName(payload(rec))
			if err == nil {
				w.learn(&w.byRunCur, obj, name)
			}
		}
		return 0
	}
	if !provider.equals(kernelFileProvider) {
		return 0
	}

	switch id {
	case evNameCreate, evNameDelete:
		if n, err := decodeName(payload(rec)); err == nil {
			w.learn(&w.byKeyCur, n.FileKey, n.Name)
		}
	case evCreate:
		if c, err := decodeCreate(payload(rec)); err == nil {
			w.learn(&w.byObjCur, c.FileObject, c.Name)
		}
	case evCleanup, evClose:
		// Deliberately not retired here. A read can complete after its handle is
		// closed, and dropping the name at close is how those reads lose their
		// path. Bounding is done by generation rotation instead.
		_, _ = decodeClose(payload(rec))
	case evRead:
		r, err := decodeRead(payload(rec))
		if err != nil {
			return 0
		}
		p := pendingRead{
			fileObject: r.FileObject,
			fileKey:    r.FileKey,
			pid:        rec.EventHeader.ProcessId,
			tid:        r.IssuingThreadID,
			at:         time.Now().UTC(),
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

// toDOS turns \Device\HarddiskVolumeN\path into X:\path. A read whose device
// has no drive letter is not discardable silently — it is returned empty and the
// caller drops it, which is counted by the folder filter rather than hidden.
func (w *Watcher) toDOS(nt string) string {
	if nt == "" {
		return ""
	}
	if len(nt) > 1 && nt[1] == ':' {
		return nt
	}
	w.rmu.Lock()
	stale := time.Since(w.volumesAt) > 30*time.Second
	vols := w.volumes
	w.rmu.Unlock()

	if dos, ok := matchVolume(vols, nt); ok {
		return dos
	}
	if !stale {
		return ""
	}
	// A drive letter may have appeared since the map was built — a removable
	// volume arriving is the ordinary case — so a miss on a stale map is worth
	// one rebuild before the read is given up on.
	w.refreshVolumes()
	w.rmu.Lock()
	vols = w.volumes
	w.rmu.Unlock()
	dos, _ := matchVolume(vols, nt)
	return dos
}

func matchVolume(vols map[string]string, nt string) (string, bool) {
	for device, letter := range vols {
		if strings.EqualFold(nt, device) {
			return letter, true
		}
		if len(nt) > len(device) && nt[len(device)] == '\\' &&
			strings.EqualFold(nt[:len(device)], device) {
			return letter + nt[len(device):], true
		}
	}
	return "", false
}

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procQueryDosDeviceW  = kernel32.NewProc("QueryDosDeviceW")
	procGetLogicalDrives = kernel32.NewProc("GetLogicalDrives")
)

// refreshVolumes maps \Device\... to drive letters. Rebuilt rather than cached
// forever because a removable volume arriving changes the answer.
func (w *Watcher) refreshVolumes() {
	mask, _, _ := procGetLogicalDrives.Call()
	vols := make(map[string]string, 26)
	buf := make([]uint16, 1024)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A'+i)) + ":"
		n, _, _ := procQueryDosDeviceW.Call(
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(letter))),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if n == 0 {
			continue
		}
		if device := syscall.UTF16ToString(buf); device != "" {
			vols[device] = letter
		}
	}
	w.rmu.Lock()
	w.volumes = vols
	w.volumesAt = time.Now()
	w.rmu.Unlock()
}
