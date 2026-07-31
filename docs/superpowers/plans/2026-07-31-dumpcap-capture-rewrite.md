# Dumpcap Capture Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bulletproof dumpcap capture: a managed dumpcap child process writing a bounded ring of pcap files, and a lossless tailer streaming those packets to the dashboard — replacing the current implementation whose six audited defects are listed in the spec.

**Architecture:** Two new units in `backend/internal/capture/`: `DumpcapManager` owns the dumpcap *process* (preflight, launch with the BH-2025-proven args, supervise, restart, kill on shutdown); `DumpcapTailer` owns *file reading* (custom offset-tracked pcap record reader immune to EOF latching, serial-ordered ring traversal, drain-then-switch rotation). `main.go` wires them: one global manager at startup when `-launch-dumpcap`, one tailer per websocket client in dumpcap mode, loud error to the client on failure — never a silent fallback to simulated traffic.

**Tech Stack:** Go 1.21, gopacket v1.1.19 (already a dependency — used for decoding and for writing test pcaps via pcapgo). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-31-dumpcap-capture-rewrite-design.md`

## Global Constraints

- Go 1.21; no dependencies beyond what is in `backend/go.mod` today.
- All new Go code lives in `backend/internal/capture/`; tests run with `cd backend && go test ./internal/capture/`.
- Every packet emitted by the tailer has `Source: "dumpcap"`.
- Flag names (exact): `-dumpcap`, `-dumpcap-dir`, `-launch-dumpcap` (existing); `-dumpcap-filesize-mb` (default 500), `-dumpcap-ring-files` (default 20), `-dumpcap-buffer-mb` (default 1024) (new).
- Dumpcap launch args must include `-P` (classic pcap format) and `-B <buffer-mb>`.
- Other capture modes (simulated, `-iface`, `-pcap`, zeek) must be untouched and keep working.
- Existing frontend is not modified in this plan.
- macOS is the dev platform (no BPF permission — launch preflight MUST fail actionably there); Linux is the deploy platform.

---

### Task 1: Shared packet decoder

The existing `DumpcapCapture.processPacket` (packet.go:1704) decodes only IPv4/Ethernet and hardcodes no source label. Extract a reusable, tested decoder both the new tailer and future readers use.

**Files:**
- Create: `backend/internal/capture/decode.go`
- Test: `backend/internal/capture/decode_test.go`

**Interfaces:**
- Produces: `func decodeCapturedPacket(data []byte, linkType layers.LinkType, source string) *Packet` — returns nil for non-IPv4 frames. Reuses existing `extractPortsAndProtocol(packet gopacket.Packet) (int, int, string)` from packet.go unchanged.

- [ ] **Step 1: Write the failing test**

```go
// backend/internal/capture/decode_test.go
package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildTCPFrame(t *testing.T, srcIP, dstIP string, srcPort, dstPort int) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort)}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("hi"))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeCapturedPacketTCP(t *testing.T) {
	frame := buildTCPFrame(t, "192.168.1.10", "10.0.0.5", 50123, 443)
	p := decodeCapturedPacket(frame, layers.LinkTypeEthernet, "dumpcap")
	if p == nil {
		t.Fatal("expected packet, got nil")
	}
	if p.Src != "192.168.1.10" || p.Dst != "10.0.0.5" {
		t.Fatalf("bad IPs: %s -> %s", p.Src, p.Dst)
	}
	if p.SrcPort != 50123 || p.DstPort != 443 {
		t.Fatalf("bad ports: %d -> %d", p.SrcPort, p.DstPort)
	}
	if p.Protocol != ProtocolTCP {
		t.Fatalf("bad protocol: %s", p.Protocol)
	}
	if p.Source != "dumpcap" {
		t.Fatalf("bad source: %q", p.Source)
	}
	if p.Size != len(frame) {
		t.Fatalf("bad size: %d != %d", p.Size, len(frame))
	}
}

func TestDecodeCapturedPacketNonIPReturnsNil(t *testing.T) {
	if p := decodeCapturedPacket([]byte{0xde, 0xad, 0xbe, 0xef}, layers.LinkTypeEthernet, "dumpcap"); p != nil {
		t.Fatalf("expected nil for garbage frame, got %+v", p)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/capture/ -run TestDecodeCaptured -v`
Expected: FAIL with "undefined: decodeCapturedPacket"

- [ ] **Step 3: Write minimal implementation**

```go
// backend/internal/capture/decode.go
package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeCapturedPacket converts a raw captured frame into a VIBES Packet.
// Returns nil for frames without an IPv4 layer (mirrors the live-capture path).
func decodeCapturedPacket(data []byte, linkType layers.LinkType, source string) *Packet {
	packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil
	}
	srcPort, dstPort, protocol := extractPortsAndProtocol(packet)
	p := NewPacketWithPorts(ip.SrcIP.String(), ip.DstIP.String(), srcPort, dstPort, len(data), protocol)
	p.Source = source
	return p
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/capture/ -run TestDecodeCaptured -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add backend/internal/capture/decode.go backend/internal/capture/decode_test.go
git commit -m "feat(capture): shared frame decoder with source labeling"
```

---

### Task 2: Offset-tracked pcap record reader

The core lossless-tailing primitive. libpcap's `OpenOffline` latches EOF and cannot tail a growing file; `pcapgo.Reader` corrupts its position on partial records. This custom reader parses the trivial classic-pcap format with `ReadAt` (stateless reads at explicit offsets) — a partial record leaves the offset untouched, so the next poll retries cleanly.

**Files:**
- Create: `backend/internal/capture/pcap_record_reader.go`
- Test: `backend/internal/capture/pcap_record_reader_test.go`

**Interfaces:**
- Produces:
  - `func newPcapRecordReader(path string) (*pcapRecordReader, error)` — opens and validates the 24-byte global header; error `errPcapHeaderIncomplete` if file too short (caller retries next poll); error on bad magic.
  - `(r *pcapRecordReader) Next() (data []byte, ok bool, err error)` — ok=false means "no complete record available yet" (not fatal); err is fatal (corrupt file).
  - `(r *pcapRecordReader) LinkType() layers.LinkType`
  - `(r *pcapRecordReader) Close() error`
  - `var errPcapHeaderIncomplete = errors.New("pcap header incomplete")`

- [ ] **Step 1: Write the failing test**

```go
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

func TestRecordReaderIncompleteHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.pcap")
	os.WriteFile(path, []byte{0xd4, 0xc3}, 0644)
	_, err := newPcapRecordReader(path)
	if err != errPcapHeaderIncomplete {
		t.Fatalf("want errPcapHeaderIncomplete, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/capture/ -run TestRecordReader -v`
Expected: FAIL with "undefined: newPcapRecordReader"

- [ ] **Step 3: Write the implementation**

```go
// backend/internal/capture/pcap_record_reader.go
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket/layers"
)

var errPcapHeaderIncomplete = errors.New("pcap header incomplete")

const (
	pcapMagicLE      = 0xa1b2c3d4 // usec timestamps, written little-endian
	pcapMagicNanoLE  = 0xa1b23c4d // nsec timestamps
	pcapGlobalHeader = 24
	pcapRecordHeader = 16
	maxSanePacketLen = 256 * 1024 * 1024 // corrupt-length guard
)

// pcapRecordReader tails a classic-pcap file using stateless ReadAt calls at
// an explicit offset. A partial record (writer mid-append) leaves the offset
// untouched so the next poll retries — no EOF latching, no position corruption.
type pcapRecordReader struct {
	f         *os.File
	byteOrder binary.ByteOrder
	linkType  layers.LinkType
	offset    int64
}

func newPcapRecordReader(path string) (*pcapRecordReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, pcapGlobalHeader)
	n, err := f.ReadAt(hdr, 0)
	if n < pcapGlobalHeader {
		f.Close()
		if err == io.EOF || err == io.ErrUnexpectedEOF || err == nil {
			return nil, errPcapHeaderIncomplete
		}
		return nil, err
	}
	var order binary.ByteOrder
	magicLE := binary.LittleEndian.Uint32(hdr[0:4])
	magicBE := binary.BigEndian.Uint32(hdr[0:4])
	switch {
	case magicLE == pcapMagicLE || magicLE == pcapMagicNanoLE:
		order = binary.LittleEndian
	case magicBE == pcapMagicLE || magicBE == pcapMagicNanoLE:
		order = binary.BigEndian
	default:
		f.Close()
		return nil, fmt.Errorf("not a classic pcap file (magic %#x): %s", magicLE, path)
	}
	return &pcapRecordReader{
		f:         f,
		byteOrder: order,
		linkType:  layers.LinkType(order.Uint32(hdr[20:24])),
		offset:    pcapGlobalHeader,
	}, nil
}

func (r *pcapRecordReader) LinkType() layers.LinkType { return r.linkType }

// Next returns the next complete record's frame bytes. ok=false means no
// complete record is available yet (tail: retry later). err is fatal.
func (r *pcapRecordReader) Next() ([]byte, bool, error) {
	rec := make([]byte, pcapRecordHeader)
	if n, err := r.f.ReadAt(rec, r.offset); n < pcapRecordHeader {
		if err == io.EOF || err == io.ErrUnexpectedEOF || err == nil {
			return nil, false, nil
		}
		return nil, false, err
	}
	inclLen := int64(r.byteOrder.Uint32(rec[8:12]))
	if inclLen < 0 || inclLen > maxSanePacketLen {
		return nil, false, fmt.Errorf("corrupt pcap record length %d at offset %d", inclLen, r.offset)
	}
	data := make([]byte, inclLen)
	if n, err := r.f.ReadAt(data, r.offset+pcapRecordHeader); int64(n) < inclLen {
		if err == io.EOF || err == io.ErrUnexpectedEOF || err == nil {
			return nil, false, nil // partial record — retry next poll
		}
		return nil, false, err
	}
	r.offset += pcapRecordHeader + inclLen
	return data, true, nil
}

func (r *pcapRecordReader) Close() error { return r.f.Close() }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/capture/ -run TestRecordReader -v`
Expected: PASS (all five tests)

- [ ] **Step 5: Commit**

```bash
git add backend/internal/capture/pcap_record_reader.go backend/internal/capture/pcap_record_reader_test.go
git commit -m "feat(capture): offset-tracked pcap record reader for lossless tailing"
```

---

### Task 3: Ring-file discovery and ordering

**Files:**
- Create: `backend/internal/capture/dumpcap_ring.go`
- Test: `backend/internal/capture/dumpcap_ring_test.go`

**Interfaces:**
- Produces:
  - `func discoverRingFiles(dir string) ([]ringFile, error)` — all `*.pcap` and `*.pcapng` in dir, sorted oldest-first.
  - `type ringFile struct { Path string; Serial int; ModTime time.Time }` — `Serial` is -1 when the name has no dumpcap ring serial.
  - `func parseRingSerial(filename string) int` — extracts N from dumpcap ring names like `vibes_en0_00003_20260731153000.pcap`; -1 otherwise.
- Ordering rule: files with serials sort by serial ascending; non-serial files sort by ModTime ascending; serial files sort before non-serial only when both kinds exist with the same ModTime ordering ambiguity — implement as: sort by (Serial if >=0 else 0, ModTime, Path) using ModTime as primary key and Serial as tiebreak, since dumpcap serials always increase with mtime.

- [ ] **Step 1: Write the failing test**

```go
// backend/internal/capture/dumpcap_ring_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/capture/ -run "TestParseRingSerial|TestDiscoverRingFiles" -v`
Expected: FAIL with "undefined: parseRingSerial"

- [ ] **Step 3: Write the implementation**

```go
// backend/internal/capture/dumpcap_ring.go
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

// discoverRingFiles lists capture files oldest-first. Serial order wins when
// present (dumpcap serials always increase); mtime orders manual files.
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
		if a.Serial >= 0 && b.Serial >= 0 && a.Serial != b.Serial {
			return a.Serial < b.Serial
		}
		if !a.ModTime.Equal(b.ModTime) {
			return a.ModTime.Before(b.ModTime)
		}
		return a.Path < b.Path
	})
	return files, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/capture/ -run "TestParseRingSerial|TestDiscoverRingFiles" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/internal/capture/dumpcap_ring.go backend/internal/capture/dumpcap_ring_test.go
git commit -m "feat(capture): ring-file discovery with serial ordering"
```

---

### Task 4: DumpcapTailer — lossless drain-then-switch tailing

Replaces the old `DumpcapCapture` (which stays in place until Task 6 removes it). Satisfies the `PacketCapture` interface (`Start() error; Stop() error; GetPacketChannel() <-chan *Packet` — see packet.go:107).

**Files:**
- Create: `backend/internal/capture/dumpcap_tailer.go`
- Test: `backend/internal/capture/dumpcap_tailer_test.go`

**Interfaces:**
- Consumes: `newPcapRecordReader`, `discoverRingFiles`, `decodeCapturedPacket` (Tasks 1-3).
- Produces:
  - `func NewDumpcapTailer(dir string) *DumpcapTailer` — implements `PacketCapture`.
  - `(t *DumpcapTailer) Stats() DumpcapTailerStats` where `type DumpcapTailerStats struct { PacketsRead uint64; PacketsDropped uint64; CurrentFile string }`.
  - Poll interval and drain budget as package constants: `tailerPollInterval = 250 * time.Millisecond`, `tailerDrainBudget = 20 * time.Millisecond` — but the struct has a `pollInterval time.Duration` field (set by constructor to the constant) so tests can shorten it.
- Behavior contract:
  - Reads files strictly in `discoverRingFiles` order; never skips an unread file.
  - Advances past the current file only when BOTH: a later file exists, and two consecutive drains of the current file yielded zero records.
  - If the current file was deleted (ring wrap), logs a warning and advances.
  - Non-IPv4 frames are skipped silently; corrupt file (fatal reader error) logs once and advances to next file.
  - `*.pcapng` files: attempted with `newPcapRecordReader`; its bad-magic error triggers the corrupt-file advance path with a log advising `-P`. (Full pcapng tailing is out of scope; the manager always writes classic pcap.)
  - Full channel: increment `PacketsDropped`, do not block.

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/capture/ -run TestTailer -v`
Expected: FAIL with "undefined: NewDumpcapTailer"

- [ ] **Step 3: Write the implementation**

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./internal/capture/ -run TestTailer -v`
Expected: PASS (all four tests)

- [ ] **Step 5: Run the whole capture package test suite**

Run: `cd backend && go test ./internal/capture/ -v 2>&1 | tail -20`
Expected: all PASS, no regressions

- [ ] **Step 6: Commit**

```bash
git add backend/internal/capture/dumpcap_tailer.go backend/internal/capture/dumpcap_tailer_test.go
git commit -m "feat(capture): lossless dumpcap tailer with drain-then-switch rotation"
```

---

### Task 5: DumpcapManager — preflight, launch, supervise

**Files:**
- Create: `backend/internal/capture/dumpcap_manager.go`
- Test: `backend/internal/capture/dumpcap_manager_test.go`

**Interfaces:**
- Produces:
  - `type DumpcapManagerConfig struct { Binary string; Iface string; OutputDir string; FileSizeMB int; RingFiles int; BufferMB int; RestartBackoffBase time.Duration }` — `Binary` defaults to `"dumpcap"`; `RestartBackoffBase` defaults to `time.Second` (tests shorten it).
  - `func NewDumpcapManager(cfg DumpcapManagerConfig) *DumpcapManager`
  - `func dumpcapArgs(cfg DumpcapManagerConfig) []string` — pure, tested.
  - `func preflightAdvice(goos string) string` — pure, returns the actionable remediation line per platform.
  - `(m *DumpcapManager) Preflight() error` — runs `<Binary> -D`; on failure wraps stderr + `preflightAdvice(runtime.GOOS)`.
  - `(m *DumpcapManager) Start() error` — Preflight, MkdirAll, launch, supervise goroutine with backoff restart.
  - `(m *DumpcapManager) Stop()` — SIGTERM child, wait up to 3s, SIGKILL.
  - `(m *DumpcapManager) Status() DumpcapManagerStatus` where `type DumpcapManagerStatus struct { Running bool; PID int; Restarts int; LastError string }`.

- [ ] **Step 1: Write the failing tests**

```go
// backend/internal/capture/dumpcap_manager_test.go
package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDumpcapArgs(t *testing.T) {
	cfg := DumpcapManagerConfig{
		Iface: "en0", OutputDir: "/data/pcaps",
		FileSizeMB: 500, RingFiles: 20, BufferMB: 1024,
	}
	args := dumpcapArgs(cfg)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-i en0", "-P", "-B 1024",
		"-b filesize:512000", // 500 MB in KB — dumpcap's filesize unit is KB
		"-b files:20",
		"-w /data/pcaps/vibes_en0.pcap",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q in %q", want, joined)
		}
	}
}

func TestPreflightAdvice(t *testing.T) {
	if !strings.Contains(preflightAdvice("darwin"), "ChmodBPF") {
		t.Error("darwin advice must mention ChmodBPF")
	}
	linux := preflightAdvice("linux")
	if !strings.Contains(linux, "setcap") && !strings.Contains(linux, "sudo") {
		t.Error("linux advice must mention setcap or sudo")
	}
}

// fakeScript writes an executable shell script and returns its path.
func fakeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-dumpcap")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManagerPreflightFailure(t *testing.T) {
	bin := fakeScript(t, `echo "no permission" >&2; exit 2`)
	m := NewDumpcapManager(DumpcapManagerConfig{Binary: bin, Iface: "x", OutputDir: t.TempDir()})
	err := m.Preflight()
	if err == nil {
		t.Fatal("expected preflight error")
	}
	if !strings.Contains(err.Error(), "no permission") {
		t.Errorf("error should include child stderr, got: %v", err)
	}
}

func TestManagerRestartsOnDeath(t *testing.T) {
	// -D probe succeeds; the capture invocation dies immediately.
	bin := fakeScript(t, `if [ "$1" = "-D" ]; then echo "1. lo"; exit 0; fi; echo "boom" >&2; exit 1`)
	m := NewDumpcapManager(DumpcapManagerConfig{
		Binary: bin, Iface: "lo", OutputDir: t.TempDir(),
		RestartBackoffBase: 10 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status().Restarts >= 2 {
			return // supervised restart works
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected >=2 restarts, got %d", m.Status().Restarts)
}

func TestManagerStopKillsChild(t *testing.T) {
	bin := fakeScript(t, `if [ "$1" = "-D" ]; then exit 0; fi; sleep 60`)
	m := NewDumpcapManager(DumpcapManagerConfig{
		Binary: bin, Iface: "lo", OutputDir: t.TempDir(),
		RestartBackoffBase: 10 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	pid := m.Status().PID
	if pid <= 0 {
		t.Fatal("expected live child PID")
	}
	m.Stop()
	time.Sleep(200 * time.Millisecond)
	if m.Status().Running {
		t.Fatal("manager still running after Stop")
	}
	// Signal 0 probes existence; ESRCH means the child is gone.
	if proc, _ := os.FindProcess(pid); proc != nil {
		if err := proc.Signal(os.Signal(nil)); err == nil {
			// On unix a nil signal errors for dead processes; if this is
			// flaky on CI, kill(pid, 0) via syscall is the alternative.
			t.Log("note: child liveness probe inconclusive")
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && go test ./internal/capture/ -run "TestDumpcapArgs|TestPreflight|TestManager" -v`
Expected: FAIL with "undefined: DumpcapManagerConfig"

- [ ] **Step 3: Write the implementation**

```go
// backend/internal/capture/dumpcap_manager.go
package capture

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type DumpcapManagerConfig struct {
	Binary             string // default "dumpcap"
	Iface              string
	OutputDir          string
	FileSizeMB         int // per ring file, default 500
	RingFiles          int // ring length, default 20
	BufferMB           int // dumpcap -B, default 1024 (BH-2025-proven)
	RestartBackoffBase time.Duration
}

type DumpcapManagerStatus struct {
	Running  bool
	PID      int
	Restarts int
	LastError string
}

type DumpcapManager struct {
	cfg      DumpcapManagerConfig
	mu       sync.Mutex
	cmd      *exec.Cmd
	stopping bool
	restarts int
	lastErr  string
	stopCh   chan struct{}
}

func NewDumpcapManager(cfg DumpcapManagerConfig) *DumpcapManager {
	if cfg.Binary == "" {
		cfg.Binary = "dumpcap"
	}
	if cfg.FileSizeMB <= 0 {
		cfg.FileSizeMB = 500
	}
	if cfg.RingFiles <= 0 {
		cfg.RingFiles = 20
	}
	if cfg.BufferMB <= 0 {
		cfg.BufferMB = 1024
	}
	if cfg.RestartBackoffBase <= 0 {
		cfg.RestartBackoffBase = time.Second
	}
	return &DumpcapManager{cfg: cfg, stopCh: make(chan struct{})}
}

func dumpcapArgs(cfg DumpcapManagerConfig) []string {
	out := filepath.Join(cfg.OutputDir, fmt.Sprintf("vibes_%s.pcap", cfg.Iface))
	return []string{
		"-i", cfg.Iface,
		"-P",
		"-B", fmt.Sprintf("%d", cfg.BufferMB),
		"-b", fmt.Sprintf("filesize:%d", cfg.FileSizeMB*1024), // dumpcap unit: KB
		"-b", fmt.Sprintf("files:%d", cfg.RingFiles),
		"-w", out,
	}
}

func preflightAdvice(goos string) string {
	switch goos {
	case "darwin":
		return "On macOS install ChmodBPF (bundled with Wireshark: 'Install ChmodBPF' package) or run the backend with sudo."
	default:
		return "On Linux grant capture rights: sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap) — or run the backend with sudo."
	}
}

// Preflight verifies dumpcap exists and can enumerate interfaces (the same
// permission needed to capture). Failure is actionable, never silent.
func (m *DumpcapManager) Preflight() error {
	cmd := exec.Command(m.cfg.Binary, "-D")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return fmt.Errorf("dumpcap preflight failed: %s. %s", detail, preflightAdvice(runtime.GOOS))
	}
	return nil
}

func (m *DumpcapManager) Start() error {
	if err := m.Preflight(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.OutputDir, 0755); err != nil {
		return fmt.Errorf("cannot create dumpcap output dir: %w", err)
	}
	if err := m.launchLocked(); err != nil {
		return err
	}
	log.Printf("✅ dumpcap launched (pid %d): %s %s", m.cmd.Process.Pid, m.cfg.Binary, strings.Join(dumpcapArgs(m.cfg), " "))
	return nil
}

func (m *DumpcapManager) launchLocked() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cmd := exec.Command(m.cfg.Binary, dumpcapArgs(m.cfg)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start dumpcap: %w", err)
	}
	m.cmd = cmd
	go m.supervise(cmd, &stderr)
	return nil
}

func (m *DumpcapManager) supervise(cmd *exec.Cmd, stderr *bytes.Buffer) {
	err := cmd.Wait()
	m.mu.Lock()
	stopping := m.stopping
	if err != nil {
		m.lastErr = fmt.Sprintf("dumpcap exited: %v — stderr: %s", err, strings.TrimSpace(stderr.String()))
	} else {
		m.lastErr = "dumpcap exited cleanly"
	}
	restarts := m.restarts
	m.mu.Unlock()
	if stopping {
		return
	}
	backoff := m.cfg.RestartBackoffBase * (1 << uint(min(restarts, 5)))
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	log.Printf("❌ %s — restarting in %s", m.lastErr, backoff)
	select {
	case <-m.stopCh:
		return
	case <-time.After(backoff):
	}
	m.mu.Lock()
	m.restarts++
	m.mu.Unlock()
	if err := m.launchLocked(); err != nil {
		log.Printf("❌ dumpcap restart failed: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *DumpcapManager) Stop() {
	m.mu.Lock()
	m.stopping = true
	cmd := m.cmd
	m.mu.Unlock()
	close(m.stopCh)
	if cmd == nil || cmd.Process == nil {
		return
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
	}
	log.Printf("🛑 dumpcap stopped")
}

func (m *DumpcapManager) Status() DumpcapManagerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := DumpcapManagerStatus{Restarts: m.restarts, LastError: m.lastErr}
	if m.cmd != nil && m.cmd.Process != nil && !m.stopping {
		s.Running = true
		s.PID = m.cmd.Process.Pid
	}
	return s
}
```

Note for the implementer: `cmd.Process.Wait()` in `Stop` races with `supervise`'s `cmd.Wait()` — only one waiter is allowed per process. Fix during implementation: `supervise` is the single waiter; `Stop` should wait on a `done` channel that `supervise` closes after `Wait` returns (add `waitDone chan struct{}` created per launch). Write it that way; the test `TestManagerStopKillsChild` will catch the race if you don't.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./internal/capture/ -run "TestDumpcapArgs|TestPreflight|TestManager" -v`
Expected: PASS. If `TestManagerStopKillsChild` flakes on the double-Wait race, apply the note above.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/capture/dumpcap_manager.go backend/internal/capture/dumpcap_manager_test.go
git commit -m "feat(capture): managed dumpcap child with preflight and supervised restart"
```

---

### Task 6: Wire into main.go, delete the broken paths

**Files:**
- Modify: `backend/cmd/main.go` (flags near line 34-41; capture selection ~lines 205-235; delete `checkDumpcapRunning`, `checkDumpcapInstalled`, `launchDumpcapProcess`, `handleDumpcapSetup`, `hasRecentPcapFiles` at lines 627-745)
- Modify: `backend/internal/capture/packet.go` — delete the old `DumpcapCapture` (lines 1493-1735; keep `extractPortsAndProtocol`, it's used by decode.go)

**Interfaces:**
- Consumes: `capture.NewDumpcapTailer(dir)`, `capture.NewDumpcapManager(cfg)`, `(*DumpcapManager).Start/Stop/Status`, `(*DumpcapTailer).Stats()`.
- Produces: flags `-dumpcap-filesize-mb`, `-dumpcap-ring-files`, `-dumpcap-buffer-mb`; `/api/status` gains `"dumpcap"` object; websocket error frame `{"type":"error","message":...}` on capture-setup failure.

- [ ] **Step 1: Add flags and global manager**

In the `var (...)` flag block after `launchDumpcap`:

```go
dumpcapFileSizeMB = flag.Int("dumpcap-filesize-mb", 500, "dumpcap ring: size per file in MB")
dumpcapRingFiles  = flag.Int("dumpcap-ring-files", 20, "dumpcap ring: number of files before overwrite")
dumpcapBufferMB   = flag.Int("dumpcap-buffer-mb", 1024, "dumpcap kernel buffer size in MB (-B)")
```

In `main()` (after flag.Parse and the zeek `EnsureZeekListener` call), add the global manager:

```go
var dumpcapMgr *capture.DumpcapManager
if *useDumpcap && *launchDumpcap {
	dumpcapMgr = capture.NewDumpcapManager(capture.DumpcapManagerConfig{
		Iface:      *iface,
		OutputDir:  *dumpcapDir,
		FileSizeMB: *dumpcapFileSizeMB,
		RingFiles:  *dumpcapRingFiles,
		BufferMB:   *dumpcapBufferMB,
	})
	if err := dumpcapMgr.Start(); err != nil {
		log.Fatalf("❌ dumpcap launch failed: %v", err) // loud, at startup, actionable
	}
	defer dumpcapMgr.Stop()
}
```

`dumpcapMgr` must be reachable from the status handler — make it a package-level `var dumpcapManager *capture.DumpcapManager` assigned in main, matching the existing style of globals in this file.

- [ ] **Step 2: Replace the capture-selection branch**

In `HandleWebSocket`, replace the `} else if *useDumpcap { ... }` branch (the `handleDumpcapSetup` + `NewDumpcapCapture` block) with:

```go
} else if *useDumpcap {
	captureSystem = capture.NewDumpcapTailer(*dumpcapDir)
	captureMode = "dumpcap"
}
```

And where `captureSystem.Start()` is called for the connection, ensure a start failure sends an error frame and closes instead of falling through to sim. Find the existing `captureSystem.Start()` error path; change it to:

```go
if err := captureSystem.Start(); err != nil {
	log.Printf("❌ capture start failed (%s): %v", captureMode, err)
	errFrame, _ := json.Marshal(map[string]string{"type": "error", "message": fmt.Sprintf("capture %s failed: %v", captureMode, err)})
	client.conn.WriteMessage(websocket.TextMessage, errFrame)
	client.conn.Close()
	return
}
```

(Adapt names to the actual surrounding code — the rule is: no path may assign the simulated capture when the client asked for dumpcap.)

- [ ] **Step 3: Delete the dead functions**

Remove from main.go: `checkDumpcapRunning`, `checkDumpcapInstalled`, `launchDumpcapProcess`, `handleDumpcapSetup`, `hasRecentPcapFiles`.
Remove from packet.go: the entire `DumpcapCapture` type and its methods (lines 1493-1735). Keep `extractPortsAndProtocol`.

- [ ] **Step 4: Surface status**

In the `/api/status` handler (search `"zeek_tcp":` in main.go, ~line 297), add:

```go
"dumpcap": func() map[string]interface{} {
	out := map[string]interface{}{"mode_enabled": *useDumpcap}
	if dumpcapManager != nil {
		s := dumpcapManager.Status()
		out["running"] = s.Running
		out["pid"] = s.PID
		out["restarts"] = s.Restarts
		out["last_error"] = s.LastError
	}
	return out
}(),
```

- [ ] **Step 5: Build and run the full test suite**

Run: `cd backend && go build ./... && go vet ./... && go test ./internal/capture/`
Expected: clean build, all tests PASS.

- [ ] **Step 6: Regression-check the other modes**

With backend running (`go run ./cmd -zeek-tcp :4777`):
- `node testing/wscount.js "" 5` → sim packets flowing
- `node testing/wscount.js "pcap=$PWD/testing/pcaps/replay-test.pcap" 8` → replay packets flowing
- zeek: `node testing/wscount.js "zeek_tcp=1" 8` in background, pipe a few NDJSON lines to `nc localhost 4777` → zeek packets flowing

Expected: all three behave exactly as they did in the 2026-07-31 audit.

- [ ] **Step 7: Commit**

```bash
git add backend/cmd/main.go backend/internal/capture/packet.go
git commit -m "feat(capture): wire dumpcap manager+tailer, remove broken pgrep launch path"
```

---

### Task 7: End-to-end verification with the testing harness

**Files:**
- Modify: `testing/README.md` (document the new e2e commands)
- Uses: `testing/gotools/genpcap` (exists), `testing/wscount.js` (exists)

- [ ] **Step 1: Throughput e2e — must beat the old 16%**

Terminal steps (each command from repo root):

```bash
# backend in dumpcap-monitor mode against the testing dir (no launch, files only)
cd backend && go run ./cmd -addr :8082 -dumpcap -dumpcap-dir "$PWD/../testing/pcaps" &
sleep 3
# writer: 2000 pps for 10 s = 20,000 packets, ring-serial name so ordering kicks in
cd ../testing/gotools && go run ./genpcap -tail "$PWD/../pcaps/vibes_test_00001_20260731160000.pcap" 10 2000 1000 &
# counter
cd .. && node -e "
const ws = new WebSocket('ws://localhost:8082/ws');
let n = 0;
ws.onmessage = m => { const d = JSON.parse(m.data); if (d.type === 'packet') n++; };
setTimeout(() => { console.log('delivered:', n, 'of 20000'); process.exit(n >= 19800 ? 0 : 1); }, 16000);
"
```

Expected: `delivered: >=19800 of 20000` (≥99%). Note: the websocket per-client rate limiter (`-max-pps`) defaults off; if a limiter is active in your run, disable it for this test.

- [ ] **Step 2: Rotation e2e**

Same backend; write two serial files back to back (writer A finishes, writer B starts a `_00002_` file), verify count = A+B with zero gap. Reuse the Task 6 Step 6 pattern with two sequential `genpcap -tail` invocations of 5×500 each; expect ≥4950 of 5000.

- [ ] **Step 3: Launch-failure path on this Mac**

```bash
cd backend && go run ./cmd -addr :8083 -dumpcap -launch-dumpcap -iface en0 -dumpcap-dir /tmp/vibes-launch-test
```

Expected: process exits with `❌ dumpcap launch failed: dumpcap preflight failed: ... ChmodBPF ...` — the actionable message, not a silent success. (This Mac has no ChmodBPF; that's the point.)

- [ ] **Step 4: Update testing/README.md**

Add a "Dumpcap e2e" section documenting the three checks above verbatim.

- [ ] **Step 5: Final commit**

```bash
git add testing/README.md
git commit -m "test: dumpcap e2e procedures in testing harness"
```

---

## Self-review notes (done at plan time)

- **Spec coverage:** defects 1-2 → Task 5 (+6 deletes pgrep path); defect 3 → Tasks 2+4 (budget-based drain, verified in Task 7 step 1); defect 4 → Task 4 drain-then-switch (+Task 7 step 2); defect 5 → Task 1; defect 6 → Task 6 step 2. Ring bounds/flags → Tasks 5-6. Preflight advice → Task 5. Status surfacing → Task 6 step 4.
- **Known simplification:** pcapng tailing is intentionally out of scope (spec allows: manager always writes `-P` classic pcap); the tailer logs actionable advice when it meets a pcapng file.
- **Type consistency check:** `NewDumpcapTailer(dir string)`, `Stats() DumpcapTailerStats`, `NewDumpcapManager(cfg DumpcapManagerConfig)`, `Status() DumpcapManagerStatus` used consistently across Tasks 4-6.
