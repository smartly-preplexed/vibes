// backend/internal/capture/dumpcap_tailer.go
package capture

import (
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"
)

const (
	tailerPollInterval = 250 * time.Millisecond
	tailerDrainBudget  = 20 * time.Millisecond
)

type DumpcapTailerStats struct {
	PacketsRead    uint64
	PacketsDropped uint64
	CurrentFile    string
}

// DumpcapTailer losslessly streams packets from a directory of pcap ring
// files written by dumpcap (or any classic-pcap writer). Files are read in
// ring order; a file is left only after it is fully drained.
type DumpcapTailer struct {
	dir          string
	packetChan   chan *Packet
	stopChan     chan struct{}
	running      bool
	pollInterval time.Duration

	reader       *pcapRecordReader
	currentPath  string
	emptyDrains  int
	packetsRead  uint64
	packetsDropd uint64
	currentMu    atomic.Value // string: current path for Stats
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
	if !t.running {
		return fmt.Errorf("dumpcap tailer not running")
	}
	t.running = false
	close(t.stopChan)
	return nil
}

func (t *DumpcapTailer) GetPacketChannel() <-chan *Packet { return t.packetChan }

func (t *DumpcapTailer) Stats() DumpcapTailerStats {
	return DumpcapTailerStats{
		PacketsRead:    atomic.LoadUint64(&t.packetsRead),
		PacketsDropped: atomic.LoadUint64(&t.packetsDropd),
		CurrentFile:    t.currentMu.Load().(string),
	}
}

func (t *DumpcapTailer) loop() {
	defer func() {
		if t.reader != nil {
			t.reader.Close()
		}
		close(t.packetChan)
	}()
	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopChan:
			return
		case <-ticker.C:
			t.pollOnce()
		}
	}
}

func (t *DumpcapTailer) pollOnce() {
	files, err := discoverRingFiles(t.dir)
	if err != nil || len(files) == 0 {
		return
	}

	// No current file yet: start at the oldest.
	if t.currentPath == "" {
		t.openFile(files[0].Path)
	}

	// Current file deleted by ring wrap → advance.
	if t.currentPath != "" {
		if _, err := os.Stat(t.currentPath); err != nil {
			log.Printf("⚠️ dumpcap tailer: current file vanished (ring wrap?): %s", t.currentPath)
			t.advance(files)
		}
	}

	if t.reader == nil {
		// Defect fix: a visited-but-unreadable file (e.g. bad magic / .pcapng)
		// leaves currentPath set but reader nil. Without this, the tailer
		// would be stuck forever since the "currentPath == ''" branch above
		// never fires again. Advance past it whenever a later file exists.
		if t.currentPath != "" && t.laterFileExists(files) {
			t.advance(files)
		}
		return
	}

	n := t.drain()
	if n == 0 {
		t.emptyDrains++
	} else {
		t.emptyDrains = 0
	}

	// Drained twice with a later file available → switch.
	if t.emptyDrains >= 2 && t.laterFileExists(files) {
		t.advance(files)
	}
}

func (t *DumpcapTailer) drain() int {
	deadline := time.Now().Add(tailerDrainBudget)
	count := 0
	for time.Now().Before(deadline) {
		data, ok, err := t.reader.Next()
		if err != nil {
			log.Printf("⚠️ dumpcap tailer: fatal error in %s (%v) — advancing", t.currentPath, err)
			t.emptyDrains = 2 // force advance on next opportunity
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
				atomic.AddUint64(&t.packetsDropd, 1)
			}
		}
		count++
	}
	return count
}

func (t *DumpcapTailer) laterFileExists(files []ringFile) bool {
	for i, f := range files {
		if f.Path == t.currentPath {
			return i < len(files)-1
		}
	}
	// Current not in list at all (deleted): any file counts as later.
	return len(files) > 0
}

// advance moves to the file after currentPath (or the oldest if current is gone).
func (t *DumpcapTailer) advance(files []ringFile) {
	next := ""
	for i, f := range files {
		if f.Path == t.currentPath && i < len(files)-1 {
			next = files[i+1].Path
			break
		}
	}
	if next == "" {
		for _, f := range files {
			if f.Path != t.currentPath {
				next = f.Path
				break
			}
		}
	}
	if next == "" {
		return
	}
	t.openFile(next)
}

func (t *DumpcapTailer) openFile(path string) {
	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}
	r, err := newPcapRecordReader(path)
	if err != nil {
		if err == errPcapHeaderIncomplete {
			return // writer hasn't finished the header; retry next poll
		}
		log.Printf("⚠️ dumpcap tailer: cannot open %s: %v (pcapng? relaunch dumpcap with -P)", path, err)
		t.currentPath = path // mark as visited so advance() skips past it
		t.currentMu.Store(path)
		t.emptyDrains = 2
		return
	}
	t.reader = r
	t.currentPath = path
	t.currentMu.Store(path)
	t.emptyDrains = 0
	log.Printf("📂 dumpcap tailer: reading %s", path)
}
