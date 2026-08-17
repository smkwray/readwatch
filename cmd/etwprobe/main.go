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
	total          atomic.Uint64
	reads          atomic.Uint64
	resolved       atomic.Uint64
	unresolved     atomic.Uint64
	names          atomic.Uint64
	creates        atomic.Uint64
	opEnds         atomic.Uint64
	shortEvents    atomic.Uint64
	retired        atomic.Uint64
	rundownNames   atomic.Uint64
	otherProvider  atomic.Uint64
	completed      atomic.Uint64
	failedReads    atomic.Uint64
	emptyReads     atomic.Uint64
	pendingEvicted atomic.Uint64
	closeWouldHit  atomic.Uint64
	closeWouldMiss atomic.Uint64
}

// pendingRead is a read that has started and not yet been told whether it
// worked. Bounded, because an IRP whose completion never arrives must not grow
// the map without limit.
type pendingRead struct {
	path string
	pid  uint32
	tid  uint32
}

const pendingReadMax = 20000

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
	unresolvedByPID  map[uint32]int
	unresolvedSample []unresolvedRead
	// pending holds started reads awaiting their OperationEnd, keyed by IRP.
	pending map[uint64]pendingRead
}

func (r *resolver) pend(irp uint64, p pendingRead) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
		pending:         make(map[uint64]pendingRead, 4096),
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

func (r *resolver) name(obj, key uint64) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.byObj[obj]; ok {
		return n, true
	}
	if n, ok := r.byKey[key]; ok {
		return n, true
	}
	return "", false
}

func (r *resolver) record(path string, pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.hits[path]
	if m == nil {
		m = make(map[uint32]int)
		r.hits[path] = m
	}
	m[pid]++
}

var (
	cnt      counters
	res      = newResolver()
	filter   string
	expect   string
	verbose  bool
	callback uintptr
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
			res.byObj[obj] = name
			res.mu.Unlock()
			if rec.EventHeader.EventDescriptor.Opcode == fileIoFileRundown {
				cnt.rundownNames.Add(1)
			} else {
				cnt.names.Add(1)
			}
		case fileIoFileDelete:
			obj, _, err := decodeFileIoName(payload(rec))
			if err != nil {
				cnt.shortEvents.Add(1)
				return 0
			}
			res.mu.Lock()
			delete(res.byObj, obj)
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
		rd, err := decodeRead(b)
		if err != nil {
			cnt.shortEvents.Add(1)
			return 0
		}
		cnt.reads.Add(1)
		path, ok := res.name(rd.FileObject, rd.FileKey)
		if !ok {
			// Keeping a sample of what did NOT resolve is the difference between
			// "that file produced no read event" and "its read was among the
			// unresolved" — two claims an earlier run could not tell apart, and
			// the whole basis of the pre-open-handle finding.
			cnt.unresolved.Add(1)
			res.recordUnresolved(rd, rec.EventHeader.ProcessId)
			return 0
		}
		cnt.resolved.Add(1)
		// A Read event is the *start* of an operation. Publishing here would count
		// requests that go on to fail, be cancelled, or return nothing, and would
		// report the size asked for rather than the size delivered. Hold it until
		// OperationEnd says what happened.
		res.pend(rd.Irp, pendingRead{
			path: path,
			pid:  rec.EventHeader.ProcessId,
			tid:  rd.IssuingThreadID,
		})
	case evOperationEnd:
		cnt.opEnds.Add(1)
		oe, err := decodeOpEnd(payload(rec))
		if err != nil {
			cnt.shortEvents.Add(1)
			return 0
		}
		p, ok := res.takePending(oe.Irp)
		if !ok {
			return 0
		}
		if oe.Status != 0 {
			cnt.failedReads.Add(1)
			return 0
		}
		if oe.ExtraInformation == 0 {
			cnt.emptyReads.Add(1)
			return 0
		}
		cnt.completed.Add(1)
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
	flag.StringVar(&expect, "expect", "", "report whether this path substring was ever named, and how")
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
		if err := s.requestSystemRundown(); err != nil {
			fmt.Println("  system rundown FAILED:", err)
			fmt.Println("  (falling back to the manifest provider's own capture state)")
			if err := s.captureState(); err != nil {
				fmt.Println("  provider capture state FAILED too:", err)
			}
		} else {
			fmt.Println("  system rundown requested")
		}
		if err := s.flush(); err != nil {
			fmt.Println("  flush FAILED:", err)
		}
		// Give the rundown events a moment to be delivered before the workload
		// starts producing reads that depend on them.
		time.Sleep(500 * time.Millisecond)
		fmt.Printf("  names known after rundown: %d\n", cnt.rundownNames.Load()+cnt.names.Load())
	} else {
		fmt.Println("  rundown SKIPPED (-rundown=false)")
	}

	cpuStart := processCPU()
	wall := time.Now()
	time.Sleep(duration)
	elapsed := time.Since(wall)
	cpuUsed := processCPU() - cpuStart

	lostEvents, lostBuffers, lossKnown := s.Lost()
	s.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		fmt.Println("  ProcessTrace did not return within 5s")
	}

	report(elapsed, cpuUsed, lostEvents, lostBuffers, lossKnown)
	return nil
}

func report(elapsed, cpu time.Duration, lostEvents, lostBuffers uint32, lossKnown bool) {
	total := cnt.total.Load()
	reads := cnt.reads.Load()
	resolved := cnt.resolved.Load()
	unresolved := cnt.unresolved.Load()
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
	fmt.Printf("  close retire hit   %d  (layout confirmed by hit rate)\n", cnt.closeWouldHit.Load())
	fmt.Printf("  close retire miss  %d\n", cnt.closeWouldMiss.Load())
	fmt.Printf("  other providers    %d\n", cnt.otherProvider.Load())
	fmt.Printf("  short/undecodable  %d\n", cnt.shortEvents.Load())

	fmt.Println()
	fmt.Println("=== completion ===")
	fmt.Printf("  reads completed ok %d\n", cnt.completed.Load())
	fmt.Printf("  reads that failed  %d\n", cnt.failedReads.Load())
	fmt.Printf("  reads with 0 bytes %d\n", cnt.emptyReads.Load())
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
		fmt.Printf("  reads resolved to a path   %d/%d = %.1f%%\n", resolved, reads, 100*float64(resolved)/float64(reads))
		fmt.Printf("  reads with no known name   %d\n", unresolved)
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
		res.mu.Unlock()
		fmt.Println()
		fmt.Printf("=== expectation: %q ===\n", expect)
		fmt.Printf("  named by FileObject: %d\n", byObjHits)
		fmt.Printf("  named by FileKey:    %d\n", byKeyHits)
		if sample != "" {
			fmt.Printf("  e.g. %s\n", sample)
			fmt.Println("  → the name WAS known; the read carried an identity that did not match it")
		} else {
			fmt.Println("  → the name was never learned at all: the rundown did not cover this file")
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
