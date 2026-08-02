package capture

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ringFile struct {
	Path    string
	Serial  int
	ModTime time.Time
}

// dumpcap ring naming: <base>_<serial>_<timestamp>.<ext>, e.g. vibes_en0_00003_20260731153000.pcap
var ringSerialRe = regexp.MustCompile(`_(\d{5})_\d{8,14}\.(pcap|pcapng)$`)

func parseRingSerial(filename string) int {
	m := ringSerialRe.FindStringSubmatch(filename)
	if m == nil {
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

// discoverRingFiles lists capture files oldest-first by mtime; serial breaks ties
// for same-instant rotations. Mtime-primary ordering handles dumpcap restarts
// where serials reset to 00001, preventing new files from jumping ahead of old ones.
func discoverRingFiles(dir string) ([]ringFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []ringFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".pcap") && !strings.HasSuffix(name, ".pcapng") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, ringFile{
			Path:    filepath.Join(dir, name),
			Serial:  parseRingSerial(name),
			ModTime: info.ModTime(),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		a, b := files[i], files[j]
		if !a.ModTime.Equal(b.ModTime) {
			return a.ModTime.Before(b.ModTime)
		}
		if a.Serial != b.Serial {
			return a.Serial < b.Serial
		}
		return a.Path < b.Path
	})
	return files, nil
}
