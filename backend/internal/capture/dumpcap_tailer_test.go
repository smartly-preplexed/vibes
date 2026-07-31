// backend/internal/capture/dumpcap_tailer_test.go
package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func collectPackets(ch <-chan *Packet, max int, timeout time.Duration) []*Packet {
	var out []*Packet
	deadline := time.After(timeout)
	for {
		select {
		case p, okc := <-ch:
			if !okc {
				return out
			}
			out = append(out, p)
			if len(out) >= max {
				return out
			}
		case <-deadline:
			return out
		}
	}
}

func newTestTailer(dir string) *DumpcapTailer {
	tl := NewDumpcapTailer(dir)
	tl.pollInterval = 20 * time.Millisecond
	return tl
}

func TestTailerReadsGrowingFileBeyond100PPS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	f, _ := os.Create(path)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	appendTestPackets(t, f, w, 300)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()

	got := collectPackets(tl.GetPacketChannel(), 300, 3*time.Second)
	if len(got) != 300 {
		t.Fatalf("got %d packets in 3s, want 300 (old code capped at 100/s)", len(got))
	}
	if got[0].Source != "dumpcap" {
		t.Fatalf("source = %q, want dumpcap", got[0].Source)
	}
	// Grow the file — tail must continue.
	appendTestPackets(t, f, w, 200)
	got2 := collectPackets(tl.GetPacketChannel(), 200, 3*time.Second)
	if len(got2) != 200 {
		t.Fatalf("after growth got %d, want 200", len(got2))
	}
}

func TestTailerDrainsOldFileBeforeSwitching(t *testing.T) {
	dir := t.TempDir()
	// File 1 exists with 50 packets.
	writeTestPcap(t, dir, "vibes_en0_00001_20260731150000.pcap", 50)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	first := collectPackets(tl.GetPacketChannel(), 50, 3*time.Second)
	if len(first) != 50 {
		t.Fatalf("first file: got %d, want 50", len(first))
	}

	// Rotation: file 2 appears AND file 1 grows a final flush simultaneously.
	f1, _ := os.OpenFile(filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap"), os.O_APPEND|os.O_WRONLY, 0644)
	w1 := pcapgo.NewWriter(f1) // note: appending, header already written
	appendTestPackets(t, f1, w1, 25)
	f1.Close()
	writeTestPcap(t, dir, "vibes_en0_00002_20260731150100.pcap", 60)

	got := collectPackets(tl.GetPacketChannel(), 85, 5*time.Second)
	if len(got) != 85 {
		t.Fatalf("rotation: got %d packets, want 85 (25 tail of file1 + 60 of file2)", len(got))
	}
}

func TestTailerSurvivesDeletedCurrentFile(t *testing.T) {
	dir := t.TempDir()
	p1 := writeTestPcap(t, dir, "vibes_en0_00001_20260731150000.pcap", 20)
	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	if got := collectPackets(tl.GetPacketChannel(), 20, 3*time.Second); len(got) != 20 {
		t.Fatalf("got %d, want 20", len(got))
	}
	os.Remove(p1) // ring wrap deletes the oldest file
	writeTestPcap(t, dir, "vibes_en0_00002_20260731150100.pcap", 30)
	if got := collectPackets(tl.GetPacketChannel(), 30, 3*time.Second); len(got) != 30 {
		t.Fatalf("after delete+new file got %d, want 30", len(got))
	}
}

func TestTailerStartFailsOnMissingDir(t *testing.T) {
	tl := NewDumpcapTailer("/nonexistent/vibes-test-dir")
	if err := tl.Start(); err == nil {
		t.Fatal("expected error for missing directory")
	}
}

// TestTailerAdvancesPastUnreadableFile guards against the deadlock defect:
// if the oldest ring file has a bad magic number (e.g. someone pointed the
// tailer at a .pcapng file), openFile() fails and t.reader stays nil. The
// tailer must still advance to the next (readable) file instead of getting
// stuck forever.
func TestTailerAdvancesPastUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	// Bad-magic file that sorts first (older mtime, lower serial).
	badPath := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	junk := make([]byte, 32)
	for i := range junk {
		junk[i] = 0xEE
	}
	if err := os.WriteFile(badPath, junk, 0644); err != nil {
		t.Fatal(err)
	}
	// Ensure the good file has a strictly later mtime than the bad one.
	time.Sleep(10 * time.Millisecond)
	writeTestPcap(t, dir, "vibes_en0_00002_20260731150100.pcap", 20)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()

	got := collectPackets(tl.GetPacketChannel(), 20, 3*time.Second)
	if len(got) != 20 {
		t.Fatalf("got %d packets, want 20 (tailer must skip past unreadable file)", len(got))
	}
}
