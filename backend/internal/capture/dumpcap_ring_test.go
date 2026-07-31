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
	// Test that mtime-primary ordering handles cycle scenario: serial order disagrees
	// with mtime order. Old comparator was cyclic (f3<f2<f1<f3); new one is transitive
	// and deterministically mtime-ordered. This is a regression guard.
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)

	// f1: serial 1 (LOW), mtime base+100s (NEWEST) — post-restart file
	pf1 := filepath.Join(dir, "vibes_en0_00001_20260731170000.pcap")
	os.WriteFile(pf1, []byte("x"), 0644)
	os.Chtimes(pf1, base.Add(100*time.Second), base.Add(100*time.Second))

	// f2: no serial, mtime base+50s (MIDDLE)
	pf2 := filepath.Join(dir, "manual.pcap")
	os.WriteFile(pf2, []byte("x"), 0644)
	os.Chtimes(pf2, base.Add(50*time.Second), base.Add(50*time.Second))

	// f3: serial 2 (HIGH), mtime base+0s (OLDEST) — pre-restart file
	pf3 := filepath.Join(dir, "vibes_en0_00002_20260731150100.pcap")
	os.WriteFile(pf3, []byte("x"), 0644)
	os.Chtimes(pf3, base, base)

	files, err := discoverRingFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("found %d files, want 3", len(files))
	}

	// Verify mtime-primary order: f3 (oldest), f2 (middle), f1 (newest).
	// Serial order (f3 < f1 < f2) disagrees with mtime (f3 < f2 < f1),
	// so this was cyclic under old comparator. Now deterministically mtime-ordered.
	wantPaths := []string{pf3, pf2, pf1}
	for i, wantPath := range wantPaths {
		if files[i].Path != wantPath {
			t.Errorf("position %d: path %q, want %q", i, files[i].Path, wantPath)
		}
	}
}
