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
	total       atomic.Uint64
	reads       atomic.Uint64
	resolved    atomic.Uint64
	unresolved  atomic.Uint64
	names       atomic.Uint64
	creates     atomic.Uint64
	opEnds      atomic.Uint64
	shortEvents atomic.Uint64
}

type resolver struct {
	mu    sync.Mutex
	byKey map[uint64]string
	byObj map[uint64]string
	// hits records what actually resolved, keyed by path, with the reading PIDs.
	hits map[string]map[uint32]int
}

func newResolver() *resolver {
	return &resolver{
		byKey: make(map[uint64]string, 1<<16),
		byObj: make(map[uint64]string, 1<<16),
		hits:  make(map[string]map[uint32]int),
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
	verbose  bool
	callback uintptr
)

// eventCallback runs on ETW's thread for every event the session delivers. It
// does the least it can: copy the bytes, update maps, count. Anything expensive
// here becomes backpressure on the whole machine's file I/O reporting.
func eventCallback(rec *EVENT_RECORD) uintptr {
	cnt.total.Add(1)
	id := rec.EventHeader.EventDescriptor.Id
	switch id {
	case evNameCreate, evNameDelete:
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
			cnt.unresolved.Add(1)
			return 0
		}
		cnt.resolved.Add(1)
		if filter == "" || strings.Contains(strings.ToLower(path), filter) {
			res.record(path, rec.EventHeader.ProcessId)
		}
	case evOperationEnd:
		cnt.opEnds.Add(1)
	}
	return 0
}

func main() {
	var duration time.Duration
	flag.DurationVar(&duration, "duration", 8*time.Second, "how long to consume")
	flag.StringVar(&filter, "filter", "", "only report paths containing this (lower-case substring)")
	flag.BoolVar(&verbose, "v", false, "list every resolved path")
	rundown := flag.Bool("rundown", true, "trigger the filename rundown after starting")
	flag.Parse()
	filter = strings.ToLower(filter)

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

	time.Sleep(300 * time.Millisecond)
	if rundown {
		if err := s.captureState(); err != nil {
			fmt.Println("  rundown FAILED:", err)
		} else {
			fmt.Println("  filename rundown requested")
		}
	} else {
		fmt.Println("  filename rundown SKIPPED (-rundown=false)")
	}

	cpuStart := processCPU()
	wall := time.Now()
	time.Sleep(duration)
	elapsed := time.Since(wall)
	cpuUsed := processCPU() - cpuStart

	lostEvents, lostBuffers := s.Lost()
	s.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		fmt.Println("  ProcessTrace did not return within 5s")
	}

	report(elapsed, cpuUsed, lostEvents, lostBuffers)
	return nil
}

func report(elapsed, cpu time.Duration, lostEvents, lostBuffers uint32) {
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
	fmt.Printf("  short/undecodable  %d\n", cnt.shortEvents.Load())

	fmt.Println()
	fmt.Println("=== cost ===")
	fmt.Printf("  consumer CPU       %.3fs over %.2fs wall\n", cpu.Seconds(), secs)
	fmt.Printf("  CPU per core       %.2f%% of one core\n", 100*cpu.Seconds()/secs)
	fmt.Printf("  machine cores      %d  → %.2f%% of the machine\n", runtime.NumCPU(),
		100*cpu.Seconds()/secs/float64(runtime.NumCPU()))

	fmt.Println()
	fmt.Println("=== loss ===")
	fmt.Printf("  session EventsLost         %d\n", lostEvents)
	fmt.Printf("  session RealTimeBuffersLost %d\n", lostBuffers)

	fmt.Println()
	fmt.Println("=== resolution ===")
	if reads > 0 {
		fmt.Printf("  reads resolved to a path   %d/%d = %.1f%%\n", resolved, reads, 100*float64(resolved)/float64(reads))
		fmt.Printf("  reads with no known name   %d\n", unresolved)
	}

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
