//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// The probe answers three things the qualification matrix turns on:
//   - do reads resolve to a process and a path, including on exFAT;
//   - does filename rundown make a handle opened BEFORE the session resolvable;
//   - what does consuming the machine's whole file-read stream actually cost.

type counters struct {
	total                  atomic.Uint64
	reads                  atomic.Uint64
	resolved               atomic.Uint64
	unresolved             atomic.Uint64
	names                  atomic.Uint64
	creates                atomic.Uint64
	opEnds                 atomic.Uint64
	shortEvents            atomic.Uint64
	retired                atomic.Uint64
	rundownNames           atomic.Uint64
	otherProvider          atomic.Uint64
	completed              atomic.Uint64
	failedReads            atomic.Uint64
	emptyReads             atomic.Uint64
	pendingEvicted         atomic.Uint64
	closeWouldHit          atomic.Uint64
	closeWouldMiss         atomic.Uint64
	viaObject              atomic.Uint64
	viaKey                 atomic.Uint64
	viaRundownKey          atomic.Uint64
	viaRundownObj          atomic.Uint64
	namedLate              atomic.Uint64
	unresolvedAtCompletion atomic.Uint64
	irpCollision           atomic.Uint64
	classicReads           atomic.Uint64
	classicResolved        atomic.Uint64
	classicUnresolved      atomic.Uint64
	namesBeforeRequest     atomic.Uint64
	namesAfterRequest      atomic.Uint64
	namesAtTeardown        atomic.Uint64
	namedDeferred          atomic.Uint64
	neverNamed             atomic.Uint64
}

// pendingRead is a read that has started and not yet been told whether it
// worked. Bounded, because an IRP whose completion never arrives must not grow
// the map without limit.
type pendingRead struct {
	path       string // empty when the name had not arrived at start
	fileObject uint64
	fileKey    uint64
	pid        uint32
	tid        uint32
}

const pendingReadMax = 20000

// Phases exist so a name that arrives at shutdown can never be mistaken for one
// that answered the request. Conflating those produced a retracted conclusion.
const (
	phaseBeforeRequest int32 = 0
	phaseAfterRequest  int32 = 1
	phaseTeardown      int32 = 2
)

// unresolvedRead is one read whose file could not be named. Bounded: this is a
// diagnostic sample, not a log.
type unresolvedRead struct {
	FileObject uint64
	FileKey    uint64
	Irp        uint64
	PID        uint32
	TID        uint32
}

const unresolvedSampleMax = 200

type resolver struct {
	mu    sync.Mutex
	byKey map[uint64]string
	byObj map[uint64]string
	// hits records what actually resolved, keyed by path, with the reading PIDs.
	hits map[string]map[uint32]int
	// unresolvedByPID counts what could not be named, per reading process, plus a
	// bounded sample of the raw identities so a specific case can be traced.
	unresolvedByPID map[uint32]int
	readsByPID      map[uint32]int
	publishedByPID  map[uint32]int
	statusByPID     map[uint32]map[uint32]int
	noStartByPID    map[uint32]int
	pathsByPID      map[uint32]map[string]int
	emptyByPID      map[uint32]int
	failedByPID     map[uint32]int
	unnamedByPID    map[uint32]int
	unnamedKeyByPID map[uint32]map[uint64]int
	// deferred holds reads that completed before anything had published a name
	// for their FileKey. A read of a handle opened before the session starts is
	// the normal case for this: the only thing that can name it is the rundown,
	// and the rundown record for that handle is not delivered when CAPTURE_STATE
	// is requested - it arrives later, in this host's runs at session teardown.
	// Dropping such a read is a false negative on a file that really was read, so
	// it is parked here by FileKey and emitted if a name ever turns up.
	deferred         map[uint64][]pendingRead
	deferredHeld     int
	emptySample      []pendingRead
	unresolvedSample []unresolvedRead
	// byRundown holds names learned from the classic FileIo rundown. It is kept
	// apart from byObj on purpose: classic FileIo documents the value on its
	// Name/Rundown events as the thing a read's *FileKey* matches, which is a
	// different namespace from the manifest provider's FileObject. Keeping them
	// separate is what lets a run say which correlation actually resolved a read
	// rather than leaving it to inference.
	byRundown map[uint64]string
	// pending holds started reads awaiting their OperationEnd, keyed by IRP.
	pending map[uint64]pendingRead
	// unnamedCompletions are reads that succeeded and still had no path even at
	// completion. These, not the start-time misses, are the real evidence of an
	// identity that never correlates.
	unnamedCompletions []pendingRead
	// classicHits is the same accounting for the classic read stream, kept apart
	// so the two providers can be compared rather than blended.
	classicHits map[string]map[uint32]int
}

func (r *resolver) recordClassic(path string, pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.classicHits[path]
	if m == nil {
		m = make(map[uint32]int)
		r.classicHits[path] = m
	}
	m[pid]++
}

// recordUnnamedCompletion keeps both a full count and a bounded sample. Those
// are different things, and conflating them is what made an earlier run report
// "0 unnamed completions" for the target: the sample had filled with other
// processes, so its length said nothing about this one.
func (r *resolver) recordUnnamedCompletion(p pendingRead) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unnamedByPID[p.pid]++
	km := r.unnamedKeyByPID[p.pid]
	if km == nil {
		km = make(map[uint64]int)
		r.unnamedKeyByPID[p.pid] = km
	}
	km[p.fileKey]++
	if len(r.unnamedCompletions) < unresolvedSampleMax {
		r.unnamedCompletions = append(r.unnamedCompletions, p)
	}
}

// parkUnnamed holds a completed read whose file nothing had named yet, so a
// name arriving later can still claim it. Bounded: a run that parks more than
// this is reporting a broken correlation, not accumulating a backlog worth
// keeping.
const deferredMax = 50000

func (r *resolver) parkUnnamed(p pendingRead) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deferredHeld >= deferredMax {
		return
	}
	r.deferred[p.fileKey] = append(r.deferred[p.fileKey], p)
	r.deferredHeld++
}

// sweepDeferred retries every parked read once the stream has been consumed to
// its end. This is the whole point of parking: on this host the rundown record
// for a handle opened before the session is not delivered when CAPTURE_STATE is
// requested, so a read of it can only be named after the fact.
func (r *resolver) sweepDeferred() (resolved, stillUnnamed int) {
	r.mu.Lock()
	parked := r.deferred
	r.deferred = make(map[uint64][]pendingRead)
	r.mu.Unlock()
	for key, reads := range parked {
		for _, p := range reads {
			name, src := r.name(p.fileObject, key)
			if src == sourceNone {
				stillUnnamed++
				cnt.neverNamed.Add(1)
				continue
			}
			resolved++
			cnt.namedDeferred.Add(1)
			r.mu.Lock()
			pm := r.pathsByPID[p.pid]
			if pm == nil {
				pm = make(map[string]int)
				r.pathsByPID[p.pid] = pm
			}
			pm[name]++
			r.mu.Unlock()
			r.record(name, p.pid)
		}
	}
	return resolved, stillUnnamed
}

// nameSource says which correlation resolved a read, so the probe can report
// whether the rundown is pulling its weight.
type nameSource int

const (
	sourceNone nameSource = iota
	sourceObject
	sourceKey
	sourceRundownAsKey
	sourceRundownAsObject
)

func (r *resolver) pend(irp uint64, p pendingRead) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.pending[irp]; dup {
		// An IRP already in flight means a reused address. Quarantining both is
		// the only safe answer: publishing either could attach one operation's
		// outcome to the other's file.
		delete(r.pending, irp)
		cnt.irpCollision.Add(1)
		return
	}
	if len(r.pending) >= pendingReadMax {
		// Drop the whole generation rather than grow without bound or evict
		// arbitrarily. Counted, so a run that hits this is visibly degraded
		// rather than quietly lossy.
		cnt.pendingEvicted.Add(uint64(len(r.pending)))
		r.pending = make(map[uint64]pendingRead, pendingReadMax)
	}
	r.pending[irp] = p
}

func (r *resolver) takePending(irp uint64) (pendingRead, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.pending[irp]
	if ok {
		delete(r.pending, irp)
	}
	return p, ok
}

func newResolver() *resolver {
	return &resolver{
		byKey:           make(map[uint64]string, 1<<16),
		byObj:           make(map[uint64]string, 1<<16),
		hits:            make(map[string]map[uint32]int),
		unresolvedByPID: make(map[uint32]int),
		readsByPID:      make(map[uint32]int),
		publishedByPID:  make(map[uint32]int),
		statusByPID:     make(map[uint32]map[uint32]int),
		noStartByPID:    make(map[uint32]int),
		pathsByPID:      make(map[uint32]map[string]int),
		emptyByPID:      make(map[uint32]int),
		failedByPID:     make(map[uint32]int),
		unnamedByPID:    make(map[uint32]int),
		unnamedKeyByPID: make(map[uint32]map[uint64]int),
		deferred:        make(map[uint64][]pendingRead),
		byRundown:       make(map[uint64]string, 1<<18),
		pending:         make(map[uint64]pendingRead, 4096),
		classicHits:     make(map[string]map[uint32]int),
	}
}

func (r *resolver) recordUnresolved(rd readEvent, pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unresolvedByPID[pid]++
	if len(r.unresolvedSample) < unresolvedSampleMax {
		r.unresolvedSample = append(r.unresolvedSample, unresolvedRead{
			FileObject: rd.FileObject, FileKey: rd.FileKey, Irp: rd.Irp,
			PID: pid, TID: rd.IssuingThreadID,
		})
	}
}

func (r *resolver) name(obj, key uint64) (string, nameSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.byObj[obj]; ok {
		return n, sourceObject
	}
	if n, ok := r.byKey[key]; ok {
		return n, sourceKey
	}
	// The rundown's value is tried against FileKey first, because that is what
	// classic FileIo says it corresponds to, then against FileObject so a run can
	// show which reading is right instead of assuming one.
	if n, ok := r.byRundown[key]; ok {
		return n, sourceRundownAsKey
	}
	if n, ok := r.byRundown[obj]; ok {
		return n, sourceRundownAsObject
	}
	return "", sourceNone
}

func (r *resolver) record(path string, pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.publishedByPID[pid]++
	m := r.hits[path]
	if m == nil {
		m = make(map[uint32]int)
		r.hits[path] = m
	}
	m[pid]++
}

var (
	cnt           counters
	res           = newResolver()
	filter        string
	expect        string
	expectPID     int
	verbose       bool
	dumpRaw       bool
	rawDumped     atomic.Uint64
	classicDumped atomic.Uint64
	phase         atomic.Int32
	callback      uintptr
)

// eventCallback runs on ETW's thread for every event the session delivers. It
// does the least it can: copy the bytes, update maps, count. Anything expensive
// here becomes backpressure on the whole machine's file I/O reporting.
func eventCallback(rec *EVENT_RECORD) uintptr {
	cnt.total.Add(1)

	// Dispatch on the provider first. Classic FileIo and the manifest
	// Kernel-File provider number their events in overlapping spaces, so keying
	// on the number alone would decode one provider's payload with the other's
	// layout the moment both are enabled on the same session.
	if rec.EventHeader.ProviderId.equals(fileIoGUID) {
		switch rec.EventHeader.EventDescriptor.Opcode {
		case fileIoFileRundown, fileIoFileCreate, fileIoNameType:
			obj, name, err := decodeFileIoName(payload(rec))
			if err != nil || name == "" {
				cnt.shortEvents.Add(1)
				return 0
			}
			res.mu.Lock()
			res.byRundown[obj] = name
			res.mu.Unlock()
			// Count by PHASE, not by opcode. The previous version drove the
			// readiness barrier from opcode 36 alone, so "the rundown produced no
			// names" only ever meant "no opcode-36 events" — capture state could
			// have answered with type 0 or type 32 and gone uncounted. Same class
			// of error as the teardown reading: measuring one thing and concluding
			// about another.
			switch phase.Load() {
			case phaseBeforeRequest:
				cnt.namesBeforeRequest.Add(1)
			case phaseAfterRequest:
				cnt.namesAfterRequest.Add(1)
			default:
				cnt.namesAtTeardown.Add(1)
			}
			if rec.EventHeader.EventDescriptor.Opcode == fileIoFileRundown {
				cnt.rundownNames.Add(1)
			} else {
				cnt.names.Add(1)
			}
		case fileIoRead:
			// The read side from the SAME provider as the names. Classic FileIo
			// documents ReadWrite.FileKey as matching Name.FileObject, so this join
			// is contractual rather than the cross-provider guess. Layout is dumped
			// rather than assumed - guessing a layout is what produced two wrong
			// conclusions already.
			b := payload(rec)
			if dumpRaw && classicDumped.Add(1) <= 3 {
				var sb strings.Builder
				for i, x := range b {
					if i%8 == 0 && i > 0 {
						sb.WriteString(" | ")
					}
					fmt.Fprintf(&sb, "%02X", x)
				}
				fmt.Printf("RAW classic-read v%d len=%d pid=%d: %s\n",
					rec.EventHeader.EventDescriptor.Version, len(b),
					rec.EventHeader.ProcessId, sb.String())
			}
			cnt.classicReads.Add(1)
			cr, err := decodeClassicRead(b)
			if err != nil {
				cnt.shortEvents.Add(1)
				return 0
			}
			res.mu.Lock()
			name, ok := res.byRundown[cr.FileKey]
			res.mu.Unlock()
			if ok {
				cnt.classicResolved.Add(1)
				if filter == "" || strings.Contains(strings.ToLower(name), filter) {
					res.recordClassic(name, rec.EventHeader.ProcessId)
				}
			} else {
				cnt.classicUnresolved.Add(1)
			}
		case fileIoFileDelete:
			obj, _, err := decodeFileIoName(payload(rec))
			if err != nil {
				cnt.shortEvents.Add(1)
				return 0
			}
			res.mu.Lock()
			delete(res.byRundown, obj)
			res.mu.Unlock()
			cnt.retired.Add(1)
		}
		return 0
	}
	if !rec.EventHeader.ProviderId.equals(kernelFileProvider) {
		cnt.otherProvider.Add(1)
		return 0
	}

	id := rec.EventHeader.EventDescriptor.Id
	switch id {
	case evNameCreate:
		b := payload(rec)
		n, err := decodeName(b)
		if err != nil {
			cnt.shortEvents.Add(1)
			return 0
		}
		cnt.names.Add(1)
		res.mu.Lock()
		res.byKey[n.FileKey] = n.Name
		res.mu.Unlock()
	case evNameDelete:
		// This was being handled as an insertion, which is backwards: a name
		// event that says a mapping is going away was extending its life. Kernel
		// pointer values are reused, so a stale entry does not merely go missing,
		// it attributes a later read of one file to a different file entirely.
		b := payload(rec)
		n, err := decodeName(b)
		if err != nil {
			cnt.shortEvents.Add(1)
			return 0
		}
		res.mu.Lock()
		delete(res.byKey, n.FileKey)
		res.mu.Unlock()
		cnt.retired.Add(1)
	case evCleanup, evClose:
		// A FileObject is only valid until the object is freed, after which the
		// same pointer names something else, so these have to retire the mapping.
		//
		// This layout was the one decoder taken from documentation rather than
		// from a captured sample, so it was measured before being trusted: 30,770
		// of these events name a FileObject already in the map against 64 that do
		// not. A wrong layout would produce essentially all misses, so the layout
		// is right and the retirement is real work, not deletion of random keys.
		b := payload(rec)
		c, err := decodeClose(b)
		if err != nil {
			cnt.shortEvents.Add(1)
			return 0
		}
		res.mu.Lock()
		_, hit := res.byObj[c.FileObject]
		delete(res.byObj, c.FileObject)
		res.mu.Unlock()
		if hit {
			cnt.closeWouldHit.Add(1)
			cnt.retired.Add(1)
		} else {
			cnt.closeWouldMiss.Add(1)
		}
	case evCreate:
		b := payload(rec)
		c, err := decodeCreate(b)
		if err != nil {
			cnt.shortEvents.Add(1)
			return 0
		}
		cnt.creates.Add(1)
		res.mu.Lock()
		res.byObj[c.FileObject] = c.Name
		res.mu.Unlock()
	case evRead:
		b := payload(rec)
		// Dump the first few raw payloads. The decoded FileKey lands in a
		// different kernel pool from the one a tracerpt-rendered FileKey shows,
		// which means a field offset here is wrong; the bytes settle it where
		// reasoning about the schema did not.
		if dumpRaw && rawDumped.Add(1) <= 3 {
			var sb strings.Builder
			for i, x := range b {
				if i%8 == 0 && i > 0 {
					sb.WriteString(" | ")
				}
				fmt.Fprintf(&sb, "%02X", x)
			}
			fmt.Printf("RAW read v%d len=%d: %s\n",
				rec.EventHeader.EventDescriptor.Version, len(b), sb.String())
		}
		rd, err := decodeRead(b)
		if err != nil {
			cnt.shortEvents.Add(1)
			return 0
		}
		cnt.reads.Add(1)
		res.mu.Lock()
		res.readsByPID[rec.EventHeader.ProcessId]++
		res.mu.Unlock()
		path, src := res.name(rd.FileObject, rd.FileKey)
		switch src {
		case sourceObject:
			cnt.viaObject.Add(1)
		case sourceKey:
			cnt.viaKey.Add(1)
		case sourceRundownAsKey:
			cnt.viaRundownKey.Add(1)
		case sourceRundownAsObject:
			cnt.viaRundownObj.Add(1)
		}
		// A read whose name has not arrived yet is NOT discarded. Resolving once
		// at the start and throwing away the miss is what made an earlier run look
		// like a Windows identity mismatch when it was really name-stream latency:
		// the rundown's 140,211 names all landed after the reads that needed them.
		// Every start is now carried to its completion and resolved again there.
		res.pend(rd.Irp, pendingRead{
			path:       path,
			fileObject: rd.FileObject,
			fileKey:    rd.FileKey,
			pid:        rec.EventHeader.ProcessId,
			tid:        rd.IssuingThreadID,
		})
		if src == sourceNone {
			cnt.unresolved.Add(1)
			res.recordUnresolved(rd, rec.EventHeader.ProcessId)
		} else {
			cnt.resolved.Add(1)
		}
	case evOperationEnd:
		cnt.opEnds.Add(1)
		oe, err := decodeOpEnd(payload(rec))
		if err != nil {
			cnt.shortEvents.Add(1)
			return 0
		}
		p, ok := res.takePending(oe.Irp)
		if !ok {
			res.mu.Lock()
			res.noStartByPID[rec.EventHeader.ProcessId]++
			res.mu.Unlock()
			return 0
		}
		res.mu.Lock()
		m := res.statusByPID[p.pid]
		if m == nil {
			m = make(map[uint32]int)
			res.statusByPID[p.pid] = m
		}
		m[oe.Status]++
		res.mu.Unlock()
		if oe.Status != 0 {
			cnt.failedReads.Add(1)
			res.mu.Lock()
			res.failedByPID[p.pid]++
			res.mu.Unlock()
			return 0
		}
		if oe.ExtraInformation == 0 {
			cnt.emptyReads.Add(1)
			res.mu.Lock()
			res.emptyByPID[p.pid]++
			if len(res.emptySample) < 40 {
				res.emptySample = append(res.emptySample, p)
			}
			res.mu.Unlock()
			return 0
		}
		cnt.completed.Add(1)
		// Second chance: the name may have arrived between start and completion.
		if p.path == "" {
			if name, src2 := res.name(p.fileObject, p.fileKey); src2 != sourceNone {
				p.path = name
				cnt.namedLate.Add(1)
				if src2 == sourceRundownAsKey {
					cnt.viaRundownKey.Add(1)
				}
			}
		}
		if p.path == "" {
			cnt.unresolvedAtCompletion.Add(1)
			res.recordUnnamedCompletion(p)
			res.parkUnnamed(p)
			return 0
		}
		res.mu.Lock()
		pm := res.pathsByPID[p.pid]
		if pm == nil {
			pm = make(map[string]int)
			res.pathsByPID[p.pid] = pm
		}
		pm[p.path]++
		res.mu.Unlock()
		if filter == "" || strings.Contains(strings.ToLower(p.path), filter) {
			res.record(p.path, p.pid)
		}
	}
	return 0
}

func main() {
	var duration time.Duration
	flag.DurationVar(&duration, "duration", 8*time.Second, "how long to consume")
	flag.StringVar(&filter, "filter", "", "only report paths containing this (lower-case substring)")
	flag.BoolVar(&verbose, "v", false, "list every resolved path")
	flag.BoolVar(&dumpRaw, "dump-raw", false, "print the raw bytes of the first few read payloads")
	flag.StringVar(&expect, "expect", "", "report whether this path substring was ever named, and how")
	flag.IntVar(&expectPID, "expect-pid", 0, "bind the expectation report to this process only")
	rundown := flag.Bool("rundown", true, "trigger the filename rundown after starting")
	flag.Parse()
	filter = strings.ToLower(filter)
	expect = strings.ToLower(expect)

	if err := run(duration, *rundown); err != nil {
		fmt.Fprintln(os.Stderr, "etwprobe:", err)
		os.Exit(1)
	}
}

func run(duration time.Duration, rundown bool) error {
	fmt.Printf("etwprobe: provider Microsoft-Windows-Kernel-File, keywords 0x%X, %s\n", keywordsAny, duration)
	if err := checkLayout(); err != nil {
		return err
	}
	fmt.Println("  ABI layout check: ok")

	s, err := startSession()
	if err != nil {
		return err
	}
	fmt.Printf("  session %q started\n", sessionName)
	defer s.Stop()

	callback = syscall.NewCallback(eventCallback)

	// ProcessTrace blocks until the session stops, so it gets its own thread.
	done := make(chan error, 1)
	go func() { done <- s.openAndProcess(callback) }()

	// Wait for the consumer to actually be attached before asking for a rundown:
	// a fixed sleep was never readiness, and a rundown emitted before OpenTrace
	// succeeded is delivered to nobody.
	if err := s.waitConsumerReady(5 * time.Second); err != nil {
		return err
	}
	fmt.Println("  consumer attached")
	if rundown {
		// No fallback to the manifest provider's own capture state: quietly
		// swapping the mechanism under test turns a failed qualification into a
		// passing one for a different mechanism.
		phase.Store(phaseAfterRequest)
		if err := s.requestSystemRundown(); err != nil {
			return fmt.Errorf("system rundown failed, and there is no substitute for it: %w", err)
		}
		fmt.Println("  system rundown requested (pinned StartTrace handle)")
		if err := s.flush(); err != nil {
			fmt.Println("  flush FAILED:", err)
		}
		// Wait for the rundown to be *consumed*, not merely requested. The fixed
		// sleep this replaces declared readiness with zero names in hand while
		// 140,211 were still on their way, so every read that followed raced its
		// own name and was written off as an identity mismatch.
		n := waitRundownQuiet(20 * time.Second)
		fmt.Printf("  names before request: %d | after request: %d\n",
			cnt.namesBeforeRequest.Load(), n)
		if n == 0 {
			fmt.Println("  WARNING: capture state answered with no name event of any form.")
			fmt.Println("  Continuing so the run still reports what the ordinary streams resolve.")
		}
	} else {
		fmt.Println("  rundown SKIPPED (-rundown=false)")
	}

	cpuStart := processCPU()
	wall := time.Now()
	time.Sleep(duration)
	elapsed := time.Since(wall)
	cpuUsed := processCPU() - cpuStart

	phase.Store(phaseTeardown)
	lostEvents, lostBuffers, lossKnown := s.Lost()
	s.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		fmt.Println("  ProcessTrace did not return within 5s")
	}

	// Every event, including whatever the rundown delivers at teardown, has now
	// been consumed. Reads parked for want of a name get their one retry here.
	lateResolved, stillUnnamed := res.sweepDeferred()
	fmt.Printf("  deferred sweep: %d reads named after the fact, %d still unnamed\n",
		lateResolved, stillUnnamed)

	report(elapsed, cpuUsed, lostEvents, lostBuffers, lossKnown)
	return nil
}

// waitRundownQuiet returns once the rundown name stream has stopped growing for
// three consecutive intervals, or the deadline passes. Empirical rather than a
// documented completion signal, but unlike a fixed sleep it is at least a
// measurement of the thing it is waiting for.
func waitRundownQuiet(timeout time.Duration) uint64 {
	deadline := time.Now().Add(timeout)
	last, quiet := uint64(0), 0
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		now := cnt.namesAfterRequest.Load()
		if now == last && now > 0 {
			if quiet++; quiet >= 3 {
				return now
			}
		} else {
			quiet = 0
		}
		last = now
	}
	return last
}

func report(elapsed, cpu time.Duration, lostEvents, lostBuffers uint32, lossKnown bool) {
	total := cnt.total.Load()
	reads := cnt.reads.Load()
	resolved := cnt.resolved.Load()
	secs := elapsed.Seconds()

	fmt.Println()
	fmt.Println("=== volume ===")
	fmt.Printf("  elapsed            %.2fs\n", secs)
	fmt.Printf("  events delivered   %d  (%.0f/sec)\n", total, float64(total)/secs)
	fmt.Printf("  reads              %d  (%.0f/sec)\n", reads, float64(reads)/secs)
	fmt.Printf("  name events        %d\n", cnt.names.Load())
	fmt.Printf("  create events      %d\n", cnt.creates.Load())
	fmt.Printf("  operation ends     %d\n", cnt.opEnds.Load())
	fmt.Printf("  names retired      %d\n", cnt.retired.Load())
	fmt.Printf("  rundown names      %d\n", cnt.rundownNames.Load())
	fmt.Printf("  names before req   %d\n", cnt.namesBeforeRequest.Load())
	fmt.Printf("  names AFTER req    %d  (what capture state actually answered)\n", cnt.namesAfterRequest.Load())
	fmt.Printf("  names at teardown  %d  (must never resolve a startup test)\n", cnt.namesAtTeardown.Load())
	fmt.Printf("  close retire hit   %d  (layout confirmed by hit rate)\n", cnt.closeWouldHit.Load())
	fmt.Printf("  close retire miss  %d\n", cnt.closeWouldMiss.Load())
	fmt.Printf("  other providers    %d\n", cnt.otherProvider.Load())
	fmt.Printf("  short/undecodable  %d\n", cnt.shortEvents.Load())

	fmt.Println()
	fmt.Println("=== completion ===")
	fmt.Printf("  reads completed ok %d\n", cnt.completed.Load())
	fmt.Printf("  reads that failed  %d\n", cnt.failedReads.Load())
	fmt.Printf("  reads with 0 bytes %d\n", cnt.emptyReads.Load())
	fmt.Printf("  named late         %d  (name arrived between start and completion)\n", cnt.namedLate.Load())
	fmt.Printf("  unnamed at completion %d  (the only real correlation failures)\n", cnt.unresolvedAtCompletion.Load())
	fmt.Printf("  IRP collisions     %d\n", cnt.irpCollision.Load())
	fmt.Println()
	fmt.Println("=== classic stream (same provider as the names) ===")
	fmt.Printf("  classic reads      %d\n", cnt.classicReads.Load())
	fmt.Printf("  resolved via rundown key %d\n", cnt.classicResolved.Load())
	fmt.Printf("  unresolved         %d\n", cnt.classicUnresolved.Load())
	fmt.Printf("  distinct paths     %d\n", len(res.classicHits))
	fmt.Printf("  pending evicted    %d\n", cnt.pendingEvicted.Load())

	fmt.Println()
	fmt.Println("=== cost ===")
	fmt.Printf("  consumer CPU       %.3fs over %.2fs wall\n", cpu.Seconds(), secs)
	fmt.Printf("  CPU per core       %.2f%% of one core\n", 100*cpu.Seconds()/secs)
	fmt.Printf("  machine cores      %d  → %.2f%% of the machine\n", runtime.NumCPU(),
		100*cpu.Seconds()/secs/float64(runtime.NumCPU()))

	fmt.Println()
	fmt.Println("=== loss ===")
	if !lossKnown {
		fmt.Println("  UNKNOWN — the session could not be queried, so this run proves nothing about loss")
	} else {
		fmt.Printf("  session EventsLost          %d\n", lostEvents)
		fmt.Printf("  session RealTimeBuffersLost %d\n", lostBuffers)
	}

	fmt.Println()
	fmt.Println("=== resolution ===")
	if reads > 0 {
		// A read is resolved if it was ever named, whether at completion or by the
		// deferred sweep. Quoting only the completion-time figure understates the
		// mechanism by everything the rundown names late, which is most of it.
		late := cnt.namedDeferred.Load()
		total := resolved + late
		fmt.Printf("  reads resolved to a path   %d/%d = %.1f%%\n", total, reads, 100*float64(total)/float64(reads))
		fmt.Printf("    at completion            %d\n", resolved)
		fmt.Printf("    by deferred sweep        %d\n", late)
		fmt.Printf("  reads never named          %d\n", cnt.neverNamed.Load())
		fmt.Println("  resolved via:")
		fmt.Printf("    manifest FileObject      %d\n", cnt.viaObject.Load())
		fmt.Printf("    manifest FileKey         %d\n", cnt.viaKey.Load())
		fmt.Printf("    rundown matched as Key   %d\n", cnt.viaRundownKey.Load())
		fmt.Printf("    rundown matched as Obj   %d\n", cnt.viaRundownObj.Load())
	}
	// The decisive diagnostic for the pre-open gap: is the file's name absent
	// from the maps entirely (the rundown never named it), or present under an
	// identity the read did not carry (the rundown named it under a key that
	// does not match)? Those need completely different fixes, and without this
	// the two are indistinguishable.
	if expect != "" {
		res.mu.Lock()
		byObjHits, byKeyHits := 0, 0
		var sample string
		for _, n := range res.byObj {
			if strings.Contains(strings.ToLower(n), expect) {
				byObjHits++
				sample = n
			}
		}
		for _, n := range res.byKey {
			if strings.Contains(strings.ToLower(n), expect) {
				byKeyHits++
				sample = n
			}
		}
		rundownHits := 0
		for _, n := range res.byRundown {
			if strings.Contains(strings.ToLower(n), expect) {
				rundownHits++
				sample = n
			}
		}
		res.mu.Unlock()
		fmt.Println()
		fmt.Printf("=== expectation: %q ===\n", expect)
		fmt.Printf("  named by FileObject: %d\n", byObjHits)
		fmt.Printf("  named by FileKey:    %d\n", byKeyHits)
		fmt.Printf("  named by rundown:    %d\n", rundownHits)
		// Whether the name was learned is only half the question. The half that
		// decides the gap is whether a read of it was actually published.
		published, publishedReads := 0, 0
		res.mu.Lock()
		for path, pids := range res.hits {
			if !strings.Contains(strings.ToLower(path), expect) {
				continue
			}
			published++
			for _, n := range pids {
				publishedReads += n
			}
		}
		res.mu.Unlock()
		fmt.Printf("  reads published for it: %d across %d path(s)\n", publishedReads, published)

		// Put the identities side by side. If the rundown's key and the reads'
		// identities are similar-but-shifted, this decoder has an offset wrong; if
		// they are unrelated values, the two streams genuinely do not share a
		// namespace and no amount of decoding fixes it. Those need opposite work,
		// and nothing so far has told them apart.
		res.mu.Lock()
		for k, n := range res.byRundown {
			if strings.Contains(strings.ToLower(n), expect) {
				fmt.Printf("  rundown key for it:     0x%X\n", k)
				break
			}
		}
		// Show completions that stayed unnamed. The previous version printed the
		// first four *global* start-time misses, which came from unrelated
		// processes and could never have said anything about the target — the
		// claim it was used to support was not evidence.
		if len(res.unnamedCompletions) == 0 {
			fmt.Println("  no successful read completed without a name")
		}
		// Bound to the target process. Printing global unnamed completions said
		// nothing about the target and was how an earlier conclusion got made from
		// other processes' traffic.
		shown, targetUnnamed := 0, 0
		seen := map[uint64]int{}
		for _, u := range res.unnamedCompletions {
			if expectPID != 0 && int(u.pid) != expectPID {
				continue
			}
			targetUnnamed++
			seen[u.fileKey]++
			if shown < 6 {
				fmt.Printf("  target unnamed completion: FileObject=0x%X FileKey=0x%X pid=%d\n",
					u.fileObject, u.fileKey, u.pid)
				shown++
			}
		}
		if expectPID != 0 {
			pid := uint32(expectPID)
			stillPending := 0
			for _, pr := range res.pending {
				if pr.pid == pid {
					stillPending++
				}
			}
			fmt.Printf("  target pid %d: %d read starts, %d published, %d unnamed completions, %d still pending\n",
				expectPID, res.readsByPID[pid], res.publishedByPID[pid], targetUnnamed, stillPending)
			fmt.Printf("  target completion statuses (NTSTATUS -> count):\n")
			for st, n := range res.statusByPID[pid] {
				fmt.Printf("    0x%08X  %d\n", st, n)
			}
			if n := res.noStartByPID[pid]; n > 0 {
				fmt.Printf("  completions with no matching start: %d (writes and other ops, not loss)\n", n)
			}
			// What did the target's successful reads actually get named? If a read
			// of the pre-open file is named as something else, that is
			// mis-attribution, which matters far more than a miss.
			type pc struct {
				path string
				n    int
			}
			var list []pc
			for path, n := range res.pathsByPID[pid] {
				list = append(list, pc{path, n})
			}
			sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
			if n := res.emptyByPID[pid]; n > 0 {
				fmt.Printf("  target reads dropped as zero-byte: %d\n", n)
				shownE := 0
				for _, e := range res.emptySample {
					if e.pid != pid || shownE >= 4 {
						continue
					}
					name := e.path
					if name == "" {
						name = fmt.Sprintf("(unnamed) FileKey=0x%X", e.fileKey)
					}
					fmt.Printf("    zero-byte read: %s\n", name)
					shownE++
				}
			}
			sum := 0
			for _, e := range list {
				sum += e.n
			}
			fmt.Printf("  target accounting: starts=%d completions=%d named=%d published=%d\n",
				res.readsByPID[pid], func() int {
					t := 0
					for _, n := range res.statusByPID[pid] {
						t += n
					}
					return t
				}(),
				sum, res.publishedByPID[pid])
			fmt.Printf("  target failed=%d zero-byte=%d unnamed=%d (bounded sample held %d of them)\n",
				res.failedByPID[pid], res.emptyByPID[pid], res.unnamedByPID[pid], targetUnnamed)
			type kc struct {
				k uint64
				n int
			}
			var keys []kc
			for k, n := range res.unnamedKeyByPID[pid] {
				keys = append(keys, kc{k, n})
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i].n > keys[j].n })
			fmt.Printf("  target's unnamed reads carry %d distinct FileKeys (top 6):\n", len(keys))
			for i, e := range keys {
				if i >= 6 {
					break
				}
				_, inRundown := res.byRundown[e.k]
				_, inKeys := res.byKey[e.k]
				fmt.Printf("    %5d  FileKey=0x%X  in-rundown=%v  in-namemap=%v\n", e.n, e.k, inRundown, inKeys)
			}
			fmt.Printf("  target collisions=%d evicted-generations=%d\n",
				cnt.irpCollision.Load(), cnt.pendingEvicted.Load())
			fmt.Printf("  target's named reads, %d distinct paths (top 8 by count):\n", len(list))
			for i, e := range list {
				if i >= 8 {
					break
				}
				fmt.Printf("    %5d  %s\n", e.n, e.path)
			}
		}
		res.mu.Unlock()
		switch {
		case sample == "":
			fmt.Println("  → NOT NAMED: nothing ever learned this file's name")
		case publishedReads > 0:
			fmt.Printf("  e.g. %s\n", sample)
			fmt.Println("  → RESOLVED: the name was learned and a read of it was attributed")
		default:
			fmt.Printf("  e.g. %s\n", sample)
			fmt.Println("  → NAMED BUT UNMATCHED: the name is known, no read of it resolved to it")
		}
	}

	res.mu.Lock()
	if len(res.unresolvedByPID) > 0 {
		type pidCount struct {
			pid uint32
			n   int
		}
		list := make([]pidCount, 0, len(res.unresolvedByPID))
		for pid, n := range res.unresolvedByPID {
			list = append(list, pidCount{pid, n})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
		fmt.Println("  unresolved reads by process (top 10):")
		for i, e := range list {
			if i >= 10 {
				break
			}
			fmt.Printf("    pid=%-8d %d\n", e.pid, e.n)
		}
		fmt.Printf("  unresolved identities sampled: %d\n", len(res.unresolvedSample))
	}
	res.mu.Unlock()

	res.mu.Lock()
	defer res.mu.Unlock()
	if len(res.hits) == 0 {
		fmt.Println("  (nothing matched the filter)")
		return
	}
	paths := make([]string, 0, len(res.hits))
	for p := range res.hits {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	limit := len(paths)
	if !verbose && limit > 25 {
		limit = 25
	}
	fmt.Printf("  matched paths: %d\n", len(paths))
	for _, p := range paths[:limit] {
		pids := res.hits[p]
		ids := make([]string, 0, len(pids))
		for pid, n := range pids {
			ids = append(ids, fmt.Sprintf("pid=%d×%d", pid, n))
		}
		sort.Strings(ids)
		fmt.Printf("    %s  [%s]\n", volumeToLetter(p), strings.Join(ids, " "))
	}
	if limit < len(paths) {
		fmt.Printf("    … %d more (-v for all)\n", len(paths)-limit)
	}
}

// processCPU is kernel+user time for this process, which is what consuming the
// stream actually costs.
func processCPU() time.Duration {
	var creation, exit, kernel, user syscall.Filetime
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0
	}
	toDur := func(f syscall.Filetime) time.Duration {
		return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100
	}
	return toDur(kernel) + toDur(user)
}

// volumeToLetter turns \Device\HarddiskVolumeN into a drive letter, which is
// what a person recognises. Built fresh each report; production would refresh it
// on device change and keep the previous generation briefly.
var letterCache map[string]string

func volumeToLetter(nt string) string {
	if letterCache == nil {
		letterCache = make(map[string]string)
		mask, _, _ := procGetLogicalDrives.Call()
		for i := 0; i < 26; i++ {
			if uint32(mask)&(1<<uint(i)) == 0 {
				continue
			}
			letter := string(rune('A'+i)) + ":"
			buf := make([]uint16, 1024)
			n, _, _ := procQueryDosDeviceW.Call(
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(letter))),
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(len(buf)),
			)
			if n == 0 {
				continue
			}
			if dev := syscall.UTF16ToString(buf); dev != "" {
				letterCache[strings.ToLower(dev)] = letter
			}
		}
	}
	lower := strings.ToLower(nt)
	best, bestLen := "", 0
	for dev, letter := range letterCache {
		if len(dev) > bestLen && strings.HasPrefix(lower, dev) {
			best, bestLen = letter, len(dev)
		}
	}
	if best == "" {
		return nt
	}
	return best + nt[bestLen:]
}
