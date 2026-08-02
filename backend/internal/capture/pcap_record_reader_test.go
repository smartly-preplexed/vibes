// backend/internal/capture/pcap_record_reader_test.go
package capture

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// writeTestPcap writes a classic pcap with n TCP frames and returns the path.
func writeTestPcap(t *testing.T, dir, name string, n int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	appendTestPackets(t, f, w, n)
	f.Close()
	return path
}

func appendTestPackets(t *testing.T, f *os.File, w *pcapgo.Writer, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		frame := buildTCPFrame(t, "192.168.1.2", "10.0.0.9", 40000+i, 443)
		ci := gopacket.CaptureInfo{CaptureLength: len(frame), Length: len(frame)}
		if err := w.WritePacket(ci, frame); err != nil {
			t.Fatal(err)
		}
	}
	f.Sync()
}

func drainAll(t *testing.T, r *pcapRecordReader) int {
	t.Helper()
	count := 0
	for {
		_, ok, err := r.Next()
		if err != nil {
			t.Fatalf("fatal read error: %v", err)
		}
		if !ok {
			return count
		}
		count++
	}
}

func TestRecordReaderReadsAllPackets(t *testing.T) {
	path := writeTestPcap(t, t.TempDir(), "a.pcap", 250)
	r, err := newPcapRecordReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.LinkType() != layers.LinkTypeEthernet {
		t.Fatalf("bad linktype: %v", r.LinkType())
	}
	if got := drainAll(t, r); got != 250 {
		t.Fatalf("read %d packets, want 250", got)
	}
}

func TestRecordReaderTailsGrowingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grow.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	appendTestPackets(t, f, w, 10)

	r, err := newPcapRecordReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := drainAll(t, r); got != 10 {
		t.Fatalf("first drain: %d, want 10", got)
	}
	// Grow the file after EOF was hit — reader must pick up the new records.
	appendTestPackets(t, f, w, 15)
	if got := drainAll(t, r); got != 15 {
		t.Fatalf("second drain: %d, want 15", got)
	}
}

func TestRecordReaderPartialRecordRetries(t *testing.T) {
	dir := t.TempDir()
	full := writeTestPcap(t, dir, "full.pcap", 2)
	raw, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	// Truncate mid-way through the second record.
	cut := len(raw) - 10
	part := filepath.Join(dir, "part.pcap")
	if err := os.WriteFile(part, raw[:cut], 0644); err != nil {
		t.Fatal(err)
	}
	r, err := newPcapRecordReader(part)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := drainAll(t, r); got != 1 {
		t.Fatalf("drain of truncated file: %d complete records, want 1", got)
	}
	// Complete the file — the retried record must now arrive intact.
	f, err := os.OpenFile(part, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(raw[cut:])
	f.Close()
	if got := drainAll(t, r); got != 1 {
		t.Fatalf("drain after completion: %d, want 1", got)
	}
}

func TestRecordReaderRejectsBadMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pcap")
	junk := make([]byte, 24)
	binary.LittleEndian.PutUint32(junk, 0x0bad0bad)
	os.WriteFile(path, junk, 0644)
	if _, err := newPcapRecordReader(path); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

// TestRecordReaderSeekToEndSkipsExistingRecords covers the primitive Finding
// F1's cold-start tail relies on: after SeekToEnd, pre-existing records must
// not be replayed, but records appended afterward must still be delivered.
func TestRecordReaderSeekToEndSkipsExistingRecords(t *testing.T) {
	dir := t.TempDir()
	path := writeTestPcap(t, dir, "seek.pcap", 5)
	r, err := newPcapRecordReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if err := r.SeekToEnd(); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := r.Next(); err != nil || ok {
		t.Fatalf("expected no record immediately after SeekToEnd, got ok=%v err=%v", ok, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f) // appending; header already written
	appendTestPackets(t, f, w, 3)
	f.Close()

	if got := drainAll(t, r); got != 3 {
		t.Fatalf("after SeekToEnd + append: got %d, want 3 (must not replay the pre-existing 5)", got)
	}
}

// TestRecordReaderSeekToEndPartialFrontier reproduces the live-capture bug:
// dumpcap is mid-write, so the file ends with a TORN record (partial payload).
// Raw-size SeekToEnd would land mid-record and misread a garbage length; the
// boundary-scanning SeekToEnd must land on the last complete record instead,
// then deliver records appended after the torn one is completed.
func TestRecordReaderSeekToEndPartialFrontier(t *testing.T) {
	dir := t.TempDir()
	// 4 complete records, then a torn trailing record (header + only half its payload).
	full := writeTestPcap(t, dir, "full.pcap", 5)
	raw, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	// Find where the 5th record starts by re-deriving: easier to just truncate a
	// few bytes off the end so the last record is torn mid-payload.
	torn := filepath.Join(dir, "torn.pcap")
	if err := os.WriteFile(torn, raw[:len(raw)-12], 0644); err != nil {
		t.Fatal(err)
	}

	r, err := newPcapRecordReader(torn)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.SeekToEnd(); err != nil {
		t.Fatalf("SeekToEnd on torn-frontier file must not error, got %v", err)
	}
	// At the frontier boundary there must be no fatal error and no record yet.
	if _, ok, err := r.Next(); err != nil || ok {
		t.Fatalf("expected clean frontier after SeekToEnd, got ok=%v err=%v", ok, err)
	}

	// Complete the torn record, then append 2 fresh ones; all 3 (completed torn
	// + 2 new) must be delivered, none of the earlier complete records replayed.
	f, err := os.OpenFile(torn, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(raw[len(raw)-12:]) // finish the torn record
	w := pcapgo.NewWriter(f)
	appendTestPackets(t, f, w, 2)
	f.Close()

	if got := drainAll(t, r); got != 3 {
		t.Fatalf("torn-frontier: got %d, want 3 (completed torn record + 2 appended)", got)
	}
}

func TestRecordReaderIncompleteHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.pcap")
	os.WriteFile(path, []byte{0xd4, 0xc3}, 0644)
	_, err := newPcapRecordReader(path)
	if err != errPcapHeaderIncomplete {
		t.Fatalf("want errPcapHeaderIncomplete, got %v", err)
	}
}
