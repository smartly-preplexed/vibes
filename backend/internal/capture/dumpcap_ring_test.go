package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseRingSerial(t *testing.T) {
	cases := map[string]int{
		"vibes_en0_00001_20260731150000.pcap": 1,
		"vibes_en0_00042_20260731150500.pcap": 42,
		"capture_00007_20250801010101.pcapng": 7,
		"8-1-2025-BH.pcap":                    -1,
		"manual.pcap":                         -1,
	}
	for name, want := range cases {
		if got := parseRingSerial(name); got != want {
			t.Errorf("parseRingSerial(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestDiscoverRingFilesOrder(t *testing.T) {
	dir := t.TempDir()
	// Create out of alphabetical order with staggered mtimes.
	names := []string{
		"vibes_en0_00002_20260731150100.pcap",
		"vibes_en0_00001_20260731150000.pcap",
		"vibes_en0_00003_20260731150200.pcap",
		"notes.txt", // ignored
	}
	base := time.Now().Add(-time.Hour)
	for i, n := range names {
		p := filepath.Join(dir, n)
		os.WriteFile(p, []byte("x"), 0644)
		serial := parseRingSerial(n)
		if serial >= 0 {
			os.Chtimes(p, base.Add(time.Duration(serial)*time.Minute), base.Add(time.Duration(serial)*time.Minute))
		} else {
			os.Chtimes(p, base.Add(time.Duration(i)*time.Second), base.Add(time.Duration(i)*time.Second))
		}
	}
	files, err := discoverRingFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("found %d files, want 3", len(files))
	}
	for i, wantSerial := range []int{1, 2, 3} {
		if files[i].Serial != wantSerial {
			t.Errorf("position %d: serial %d, want %d", i, files[i].Serial, wantSerial)
		}
	}
}

func TestDiscoverRingFilesRestartScenario(t *testing.T) {
	// Test dumpcap restart where serial resets: old files should sort before new ones
	// even if new ones have lower serials, because mtime is primary order.
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)

	// fileA: serial 1, mtime 10:00
	p1 := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	os.WriteFile(p1, []byte("x"), 0644)
	os.Chtimes(p1, base, base)

	// fileB: serial 2, mtime 10:01
	p2 := filepath.Join(dir, "vibes_en0_00002_20260731150100.pcap")
	os.WriteFile(p2, []byte("x"), 0644)
	os.Chtimes(p2, base.Add(1*time.Minute), base.Add(1*time.Minute))

	// fileC: serial 1 (reused after restart), mtime 10:05
	p3 := filepath.Join(dir, "vibes_en0_00001_20260731160000.pcap")
	os.WriteFile(p3, []byte("x"), 0644)
	os.Chtimes(p3, base.Add(5*time.Minute), base.Add(5*time.Minute))

	files, err := discoverRingFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("found %d files, want 3", len(files))
	}

	// Verify strict mtime order: p1 (10:00), p2 (10:01), p3 (10:05)
	wantPaths := []string{p1, p2, p3}
	for i, wantPath := range wantPaths {
		if files[i].Path != wantPath {
			t.Errorf("position %d: path %q, want %q", i, files[i].Path, wantPath)
		}
	}
}

func TestDiscoverRingFilesMixedSerialNonSerial(t *testing.T) {
	// Test mixed serial and non-serial files sort strictly by mtime.
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)

	// serialA: serial 5, mtime 10:00
	pA := filepath.Join(dir, "vibes_en0_00005_20260731150000.pcap")
	os.WriteFile(pA, []byte("x"), 0644)
	os.Chtimes(pA, base, base)

	// manualB: no serial, mtime 10:01 (between serial files)
	pB := filepath.Join(dir, "manual.pcap")
	os.WriteFile(pB, []byte("x"), 0644)
	os.Chtimes(pB, base.Add(1*time.Minute), base.Add(1*time.Minute))

	// serialC: serial 10, mtime 10:02
	pC := filepath.Join(dir, "vibes_en0_00010_20260731160000.pcap")
	os.WriteFile(pC, []byte("x"), 0644)
	os.Chtimes(pC, base.Add(2*time.Minute), base.Add(2*time.Minute))

	files, err := discoverRingFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("found %d files, want 3", len(files))
	}

	// Verify mtime order regardless of serial: pA (10:00), pB (10:01), pC (10:02)
	wantPaths := []string{pA, pB, pC}
	for i, wantPath := range wantPaths {
		if files[i].Path != wantPath {
			t.Errorf("position %d: path %q, want %q", i, files[i].Path, wantPath)
		}
	}
}
