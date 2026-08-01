// backend/internal/capture/dumpcap_tailer.go
package capture

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tailerPollInterval = 250 * time.Millisecond
	tailerDrainBudget  = 20 * time.Millisecond
	// dropLogInterval controls how often the tailer reports accumulated
	// packetsDropped (channel-full drops) via a log line, per Finding F3.
	dropLogInterval = 5 * time.Second
)

type DumpcapTailerStats struct {
	PacketsRead    uint64
	PacketsDropped uint64
	CurrentFile    string
}

// DumpcapTailer losslessly streams packets from a directory of pcap ring
// files written by dumpcap (or any classic-pcap writer). Files are read in
// discoverRingFiles order; a file is left only after it is fully drained.
//
// DumpcapTailer is single-use: once Stop is called (or Start fails to be
// called again after a Stop), the instance is retired for good — create a
// fresh one via NewDumpcapTailer for the next run. This matches how callers
// use it (a new tailer per connection/session).
type DumpcapTailer struct {
	dir          string
	packetChan   chan *Packet
	stopChan     chan struct{}
	pollInterval time.Duration

	mu      sync.Mutex // guards running/stopped and the stopChan close
	running bool
	stopped bool

	// The following fields are only ever touched by the single loop()
	// goroutine, so no lock is needed for them.
	reader      *pcapRecordReader
	currentPath string
	emptyDrains int
	// visited marks files that must never be (re)selected: files that were
	// fully drained and abandoned in favor of another file, or files that
	// failed to open with a permanent (non-retryable) error. Keyed by path.
	// Pruned as files disappear from the directory listing to bound memory.
	visited map[string]bool
	// started is false until the tailer has made its very first file
	// selection. That first selection is special-cased (see
	// selectNewestAtEnd, Finding F1): it tails the newest ring file from its
	// live end rather than draining the ring from the oldest file, so a
	// fresh tailer (e.g. one created per WebSocket connection against a
	// long-lived multi-GB ring) never replays hours of stale packets as if
	// they were live. Every selection after the first uses the normal
	// oldest-first drain-then-switch behavior regardless of this flag.
	started bool
	// lastLoggedFatalPath records the path a fatal record error was last
	// logged for, so a persistently corrupt file (the sole remaining
	// candidate, with nowhere to advance to) logs once instead of flooding
	// at poll frequency (Finding F5).
	lastLoggedFatalPath string

	packetsRead    uint64
	packetsDropped uint64
	currentMu      atomic.Value // string: current path for Stats
}

func NewDumpcapTailer(dir string) *DumpcapTailer {
	t := &DumpcapTailer{
		dir:          dir,
		packetChan:   make(chan *Packet, 65536),
		stopChan:     make(chan struct{}),
		pollInterval: tailerPollInterval,
	}
	t.currentMu.Store("")
	return t
}

func (t *DumpcapTailer) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return fmt.Errorf("dumpcap tailer is single-use — create a new one")
	}
	if t.running {
		return fmt.Errorf("dumpcap tailer already running")
	}
	if _, err := os.Stat(t.dir); err != nil {
		return fmt.Errorf("dumpcap directory not accessible: %w", err)
	}
	t.running = true
	log.Printf("🚀 Dumpcap tailer watching %s", t.dir)
	go t.loop()
	return nil
}

func (t *DumpcapTailer) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return fmt.Errorf("dumpcap tailer already stopped")
	}
	if !t.running {
		return fmt.Errorf("dumpcap tailer not running")
	}
	t.running = false
	t.stopped = true
	close(t.stopChan)
	return nil
}

func (t *DumpcapTailer) GetPacketChannel() <-chan *Packet { return t.packetChan }

func (t *DumpcapTailer) Stats() DumpcapTailerStats {
	return DumpcapTailerStats{
		PacketsRead:    atomic.LoadUint64(&t.packetsRead),
		PacketsDropped: atomic.LoadUint64(&t.packetsDropped),
		CurrentFile:    t.currentMu.Load().(string),
	}
}

func (t *DumpcapTailer) loop() {
	// Finding F2: unlike every other PacketCapture implementation, this
	// tailer used to close(t.packetChan) here. That's the one channel the
	// main.go forwarder reads from with no closed-channel check, so it would
	// busy-spin at 100% CPU on the zero-value receive after Stop(). Leave
	// the channel open on exit — it matches package convention (all other
	// captures do the same) and GC reclaims it once nothing references it.
	defer func() {
		if t.reader != nil {
			t.reader.Close()
		}
	}()
	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()
	// Finding F3: report accumulated packetsDropped periodically so a full
	// channel (consumer can't keep up) is visible in the logs instead of
	// silently incrementing a counter nobody reads.
	dropTicker := time.NewTicker(dropLogInterval)
	defer dropTicker.Stop()
	var lastLoggedDropped uint64
	for {
		select {
		case <-t.stopChan:
			return
		case <-ticker.C:
			t.pollOnce()
		case <-dropTicker.C:
			total := atomic.LoadUint64(&t.packetsDropped)
			if total > lastLoggedDropped {
				log.Printf("⚠️ dumpcap tailer dropped %d packets (channel full; total %d)", total-lastLoggedDropped, total)
				lastLoggedDropped = total
			}
		}
	}
}

func (t *DumpcapTailer) pollOnce() {
	files, err := discoverRingFiles(t.dir)
	if err != nil || len(files) == 0 {
		return
	}
	t.pruneVisited(files)

	// No current target yet: pick a candidate. The very first selection this
	// tailer instance ever makes is special-cased (Finding F1) — it tails
	// the newest ring file from its live end instead of draining the ring
	// oldest-first, so a fresh tailer never replays pre-existing (stale)
	// ring contents. Every subsequent selection uses the normal
	// oldest-first drain-then-switch logic.
	if t.currentPath == "" {
		if !t.started {
			t.selectNewestAtEnd(files)
		} else {
			t.selectNext(files)
		}
		if t.currentPath == "" {
			return // nothing available (all visited, or all corrupt)
		}
	}

	// The current target (whether actively open or still pending a complete
	// header) may have vanished — e.g. a ring wrap deleted it. Check by path,
	// not by reader state, since a pending file can vanish too.
	if _, err := os.Stat(t.currentPath); err != nil {
		log.Printf("⚠️ dumpcap tailer: current file vanished (ring wrap?): %s", t.currentPath)
		t.markVisited(t.currentPath)
		t.selectNext(files)
		if t.currentPath == "" {
			return
		}
	}

	if t.reader == nil {
		// A pending target: newPcapRecordReader previously reported an
		// incomplete header. Never treat this as corrupt — retry the same
		// path every poll until the writer finishes the header.
		t.openFile(t.currentPath)
		return
	}

	n := t.drain()
	if n == 0 {
		t.emptyDrains++
	} else {
		t.emptyDrains = 0
	}

	// Drained twice with nothing new, and another candidate exists → switch.
	if t.emptyDrains >= 2 && t.firstUnvisited(files, t.currentPath) != "" {
		t.markVisited(t.currentPath)
		t.selectNext(files)
	}
}

func (t *DumpcapTailer) drain() int {
	deadline := time.Now().Add(tailerDrainBudget)
	count := 0
	for time.Now().Before(deadline) {
		data, ok, err := t.reader.Next()
		if err != nil {
			// Finding F5: log this once per file, not on every poll (a
			// persistently corrupt file with no other candidate to advance
			// to would otherwise hit this every ~250ms forever). Also don't
			// claim "advancing" — whether an advance actually happens
			// depends on whether pollOnce finds another unvisited
			// candidate, which isn't known here.
			if t.lastLoggedFatalPath != t.currentPath {
				log.Printf("⚠️ dumpcap tailer: fatal error in %s (%v)", t.currentPath, err)
				t.lastLoggedFatalPath = t.currentPath
			}
			t.emptyDrains = 2 // force an advance-or-retry check on next opportunity
			return count
		}
		if !ok {
			return count
		}
		if p := decodeCapturedPacket(data, t.reader.LinkType(), "dumpcap"); p != nil {
			select {
			case t.packetChan <- p:
				atomic.AddUint64(&t.packetsRead, 1)
			default:
				atomic.AddUint64(&t.packetsDropped, 1)
			}
		}
		count++
	}
	return count
}

// firstUnvisited returns the first file (in discoverRingFiles order) that is
// neither marked visited nor equal to exclude, or "" if none remain. Scanning
// from the start of the sorted list every time — rather than walking forward
// from the current file's index — ensures a file that arrives with an
// out-of-order (older) mtime is still picked up instead of being skipped
// forever.
func (t *DumpcapTailer) firstUnvisited(files []ringFile, exclude string) string {
	for _, f := range files {
		if f.Path == exclude {
			continue
		}
		if !t.visited[f.Path] {
			return f.Path
		}
	}
	return ""
}

func (t *DumpcapTailer) markVisited(path string) {
	if t.visited == nil {
		t.visited = make(map[string]bool)
	}
	t.visited[path] = true
}

// pruneVisited drops visited entries for files no longer present in the
// directory listing, bounding the map's memory to the current ring size.
func (t *DumpcapTailer) pruneVisited(files []ringFile) {
	if len(t.visited) == 0 {
		return
	}
	present := make(map[string]bool, len(files))
	for _, f := range files {
		present[f.Path] = true
	}
	for p := range t.visited {
		if !present[p] {
			delete(t.visited, p)
		}
	}
}

// selectNewestAtEnd performs the tailer's one-time cold-start selection
// (Finding F1): it marks every file except the newest (last in
// discoverRingFiles' oldest-first order) as visited — so the tailer never
// walks back through pre-existing ring contents — and opens the newest file
// positioned at its current end, so only packets appended from this point
// on are delivered. Called at most once per tailer instance, for the very
// first selection (see the `started` field).
func (t *DumpcapTailer) selectNewestAtEnd(files []ringFile) {
	t.started = true
	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}
	t.currentPath = ""
	t.currentMu.Store("")

	newest := files[len(files)-1]
	for _, f := range files[:len(files)-1] {
		t.markVisited(f.Path)
	}
	t.openFileAt(newest.Path, true)
	// If the newest file turned out permanently corrupt, openFileAt already
	// marked it visited and left currentPath == "". Since every older file
	// was also just marked visited above, pollOnce's normal selectNext path
	// will find nothing until a new file appears in the ring — which is
	// correct: there is nothing live left to tail.
}

// selectNext closes any open reader, clears currentPath/Stats, and opens the
// first unvisited candidate. If that candidate turns out to be permanently
// corrupt, openFile marks it visited and clears currentPath, so this loops
// to the next candidate — cascading past a run of unreadable files within a
// single call instead of needing one poll per skipped file. Leaves
// currentPath == "" if nothing usable is available.
func (t *DumpcapTailer) selectNext(files []ringFile) {
	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}
	t.currentPath = ""
	t.currentMu.Store("")
	for {
		next := t.firstUnvisited(files, "")
		if next == "" {
			return
		}
		t.openFile(next)
		if t.currentPath != "" {
			return // opened successfully, or pending on an incomplete header
		}
		// openFile marked `next` visited (permanently corrupt) — try the next.
	}
}

// openFile attempts to open path as the active target, starting from the top
// of the file (offset 0 / just past the global header). See openFileAt for
// the full success/incomplete-header/corrupt outcome contract.
func (t *DumpcapTailer) openFile(path string) {
	t.openFileAt(path, false)
}

// openFileAt attempts to open path as the active target.
//   - Success: reader/currentPath/Stats all point at path. If atEnd is true
//     the reader is additionally seeked to the file's current end (Finding
//     F1's cold-start tail) so pre-existing content in that file is not
//     replayed; otherwise reading starts from just past the global header.
//   - errPcapHeaderIncomplete: the writer hasn't finished the header yet.
//     currentPath/Stats are set to path (so pollOnce retries it next poll)
//     but it is NOT marked visited — it must never be treated as corrupt.
//     atEnd is irrelevant here since there is no reader yet to seek.
//   - Any other error: permanently corrupt (or unsupported, e.g. pcapng).
//     Marked visited so it is never selected again; currentPath/Stats are
//     cleared rather than left pointing at a file with no open reader (never
//     naming an already-closed/unopened file).
func (t *DumpcapTailer) openFileAt(path string, atEnd bool) {
	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}
	r, err := newPcapRecordReader(path)
	if err != nil {
		if err == errPcapHeaderIncomplete {
			t.currentPath = path
			t.currentMu.Store(path)
			t.emptyDrains = 0
			return
		}
		log.Printf("⚠️ dumpcap tailer: cannot open %s: %v (pcapng? relaunch dumpcap with -P)", path, err)
		t.markVisited(path)
		t.currentPath = ""
		t.currentMu.Store("")
		return
	}
	if atEnd {
		if err := r.SeekToEnd(); err != nil {
			log.Printf("⚠️ dumpcap tailer: cannot seek to end of %s: %v — starting from top instead", path, err)
		}
	}
	t.reader = r
	t.currentPath = path
	t.currentMu.Store(path)
	t.emptyDrains = 0
	if atEnd {
		log.Printf("📂 dumpcap tailer: cold start — tailing newest file %s live from its current end (ignoring any pre-existing ring contents)", path)
	} else {
		log.Printf("📂 dumpcap tailer: reading %s", path)
	}
}
