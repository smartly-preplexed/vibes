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
