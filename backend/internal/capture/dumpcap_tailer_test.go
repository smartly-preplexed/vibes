// backend/internal/capture/dumpcap_tailer_test.go
package capture

import (
	"encoding/binary"
	"log"
	"os"
	"path/filepath"
	"strings"
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

// coldStartSettle gives a freshly-started tailer time to complete its
// one-time cold-start selection (Finding F1: pick the newest file, seek to
// its live end) before the test starts appending "live" packets. Several
// poll cycles at the test tailer's 20ms interval.
const coldStartSettle = 150 * time.Millisecond

func TestTailerReadsGrowingFileBeyond100PPS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	f, _ := os.Create(path)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	time.Sleep(coldStartSettle) // let cold start land at EOF of the header-only file

	appendTestPackets(t, f, w, 300)
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
	path1 := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	f1, _ := os.Create(path1)
	w1 := pcapgo.NewWriter(f1)
	w1.WriteFileHeader(65536, layers.LinkTypeEthernet)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	time.Sleep(coldStartSettle) // let cold start land at EOF of file 1

	appendTestPackets(t, f1, w1, 50)
	first := collectPackets(tl.GetPacketChannel(), 50, 3*time.Second)
	if len(first) != 50 {
		t.Fatalf("first file: got %d, want 50", len(first))
	}

	// Rotation: file 2 appears AND file 1 grows a final flush simultaneously.
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
	p1 := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	f1, _ := os.Create(p1)
	w1 := pcapgo.NewWriter(f1)
	w1.WriteFileHeader(65536, layers.LinkTypeEthernet)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	time.Sleep(coldStartSettle)

	appendTestPackets(t, f1, w1, 20)
	f1.Close()
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

// TestTailerAdvancesPastUnreadableRotationCandidate guards against the
// deadlock defect: if a rotation candidate has a bad magic number (e.g.
// someone pointed the tailer at a .pcapng file), openFile() fails and
// t.reader stays nil. The tailer must still advance to the next (readable)
// file instead of getting stuck forever. Exercised post-cold-start via the
// normal drain-then-switch rotation path (selectNext/firstUnvisited
// cascading) — the code path a corrupt *rotation* candidate would actually
// hit in production, since Finding F1's cold-start selection only ever
// looks at the single newest file, never at older ones.
func TestTailerAdvancesPastUnreadableRotationCandidate(t *testing.T) {
	dir := t.TempDir()
	path1 := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	f1, _ := os.Create(path1)
	w1 := pcapgo.NewWriter(f1)
	w1.WriteFileHeader(65536, layers.LinkTypeEthernet)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	time.Sleep(coldStartSettle)

	appendTestPackets(t, f1, w1, 10)
	f1.Close()
	if got := collectPackets(tl.GetPacketChannel(), 10, 3*time.Second); len(got) != 10 {
		t.Fatalf("file 1 (live): got %d, want 10", len(got))
	}

	// Rotation candidate 2 is corrupt (bad magic); candidate 3 is good and
	// must still be reached.
	junk := make([]byte, 32)
	for i := range junk {
		junk[i] = 0xEE
	}
	badPath := filepath.Join(dir, "vibes_en0_00002_20260731150100.pcap")
	if err := os.WriteFile(badPath, junk, 0644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	writeTestPcap(t, dir, "vibes_en0_00003_20260731150200.pcap", 20)

	got := collectPackets(tl.GetPacketChannel(), 20, 3*time.Second)
	if len(got) != 20 {
		t.Fatalf("got %d packets, want 20 (tailer must skip past unreadable rotation candidate)", len(got))
	}
}

// --- Review fix: FINDING 1 — single-use Start/Stop safety ---

// TestTailerStopThenStartReturnsError: (a) Stop then Start returns an error,
// no panic.
func TestTailerStopThenStartReturnsError(t *testing.T) {
	dir := t.TempDir()
	writeTestPcap(t, dir, "vibes_en0_00001_20260731150000.pcap", 1)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tl.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := tl.Start(); err == nil {
		t.Fatal("expected error restarting a stopped (single-use) tailer")
	}
}

// TestTailerDoubleStopReturnsError: (b) double Stop returns an error, no
// panic (no double-close of stopChan/packetChan).
func TestTailerDoubleStopReturnsError(t *testing.T) {
	dir := t.TempDir()
	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tl.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := tl.Stop(); err == nil {
		t.Fatal("expected error on double Stop")
	}
}

// TestTailerStartStopStartSequenceDoesNotPanic: (c) a Start-Stop-Start
// sequence must never panic, run with plain (recover-free) execution — if
// pollOnce or loop's shutdown defer double-closed a channel, this test
// itself would crash the test binary rather than merely failing an
// assertion.
func TestTailerStartStopStartSequenceDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	writeTestPcap(t, dir, "vibes_en0_00001_20260731150000.pcap", 1)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tl.Stop(); err != nil {
		t.Fatal(err)
	}
	err := tl.Start()
	if err == nil {
		t.Fatal("expected error restarting after Stop")
	}
}

// --- Review fix: FINDING 2 — out-of-order (older-mtime) files must not be
// skipped forever ---

// TestTailerPicksUpOlderMtimeFileNotSkippedForever: tail file A (drain it),
// then create file B with an mtime OLDER than A (so B sorts BEFORE A in
// discoverRingFiles order), then let A go quiet with B present. B's packets
// must still be delivered — the old forward-only advance() would walk
// forward from A's index and never see B again.
func TestTailerPicksUpOlderMtimeFileNotSkippedForever(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	fA, _ := os.Create(pathA)
	wA := pcapgo.NewWriter(fA)
	wA.WriteFileHeader(65536, layers.LinkTypeEthernet)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	time.Sleep(coldStartSettle)

	appendTestPackets(t, fA, wA, 10)
	fA.Close()
	if got := collectPackets(tl.GetPacketChannel(), 10, 3*time.Second); len(got) != 10 {
		t.Fatalf("file A: got %d, want 10", len(got))
	}

	pathB := writeTestPcap(t, dir, "vibes_en0_00002_20260731150100.pcap", 15)
	older := time.Now().Add(-time.Hour)
	if err := os.Chtimes(pathB, older, older); err != nil {
		t.Fatal(err)
	}

	got := collectPackets(tl.GetPacketChannel(), 15, 3*time.Second)
	if len(got) != 15 {
		t.Fatalf("file B (older mtime): got %d, want 15 — must not be skipped forever", len(got))
	}
}

// --- Review fix: FINDING 4 — incomplete-header target must be retried, not
// skipped as corrupt, and Stats().CurrentFile must not name an
// already-closed file while pending ---

// TestTailerRetriesIncompleteHeaderUntilComplete: at cold start, the newest
// (and only unvisited) candidate has just an incomplete pcap global header
// (the writer hasn't finished it yet). The tailer must retry it every poll
// rather than treating it as permanently corrupt, and Stats().CurrentFile
// must reflect that pending target — not the older file that Finding F1's
// cold-start selection already marked visited and must never report as
// current.
func TestTailerRetriesIncompleteHeaderUntilComplete(t *testing.T) {
	dir := t.TempDir()
	// An older, complete file exists too — cold start (Finding F1) must
	// mark it visited (skip it, never drain it) rather than report it as
	// CurrentFile while B's header is still incomplete.
	pathA := writeTestPcap(t, dir, "vibes_en0_00001_20260731150000.pcap", 5)

	nameB := "vibes_en0_00002_20260731150100.pcap"
	pathB := filepath.Join(dir, nameB)
	if err := os.WriteFile(pathB, make([]byte, 10), 0644); err != nil {
		t.Fatal(err)
	}

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cf := tl.Stats().CurrentFile; cf == pathB {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cf := tl.Stats().CurrentFile; cf != pathB {
		t.Fatalf("CurrentFile = %q, want pending target %q — must not name skipped older file %q", cf, pathB, pathA)
	}

	// Now complete B with a valid header + packets.
	writeTestPcap(t, dir, nameB, 12)

	got := collectPackets(tl.GetPacketChannel(), 12, 3*time.Second)
	if len(got) != 12 {
		t.Fatalf("file B: got %d, want 12 (must retry incomplete header, not skip)", len(got))
	}

	// File A's pre-existing packets must never surface.
	more := collectPackets(tl.GetPacketChannel(), 1, 300*time.Millisecond)
	if len(more) != 0 {
		t.Fatalf("tailer replayed skipped older file %q: got unexpected extra packet", pathA)
	}
}

// --- Fix F1: cold start must tail the newest file live, never replay the
// pre-existing ring ---

// TestTailerColdStartSkipsPreExistingRingContents: N packets already exist
// in the ring's only file before the tailer starts. The tailer must not
// deliver those N stale packets — only packets appended after cold start
// (live traffic) should arrive.
//
// This must be discriminating against a start-at-oldest regression, not just
// against a total-silence one: collectPackets(ch, n, timeout) returns as
// soon as n packets arrive, so a naive "assert we got exactly N" check would
// pass even under the old buggy code — it would just collect the first N of
// the pre-existing stale packets and never notice they weren't the live
// ones. To catch that, this asserts BOTH that the live count arrives AND
// that a follow-up read comes back empty (no leftover stale packets queued
// behind them) — mirroring the already-discriminating sibling test
// TestTailerColdStartTailsOnlyNewestOfMultipleExistingFiles.
func TestTailerColdStartSkipsPreExistingRingContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vibes_en0_00001_20260731150000.pcap")
	f, _ := os.Create(path)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	appendTestPackets(t, f, w, 60) // pre-existing "stale" packets, written before Start()

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	time.Sleep(coldStartSettle) // let cold start land at EOF (past the 60 stale packets)

	appendTestPackets(t, f, w, 15) // distinct run of live packets written after cold start

	got := collectPackets(tl.GetPacketChannel(), 15, 2*time.Second)
	if len(got) != 15 {
		t.Fatalf("got %d packets, want 15 (only the live ones — must not replay the 60 pre-existing)", len(got))
	}

	// The discriminating check: under start-at-oldest, the channel would
	// still have (60 - 15) = 45 leftover stale packets queued behind the 15
	// just collected, so this follow-up read would return more. Under the
	// fix, the tailer never queued any of the 60 stale packets in the first
	// place, so this must come back empty.
	more := collectPackets(tl.GetPacketChannel(), 1, 500*time.Millisecond)
	if len(more) != 0 {
		t.Fatalf("got %d unexpected extra packet(s) after the 15 live ones — the 60 pre-existing packets were replayed (start-at-oldest regression)", len(more))
	}
}

// TestTailerColdStartTailsOnlyNewestOfMultipleExistingFiles: two ring files
// already exist at startup. Only the newest should be tailed (from its live
// end); the older, pre-existing file's contents must never be replayed,
// even after the newest goes quiet.
func TestTailerColdStartTailsOnlyNewestOfMultipleExistingFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestPcap(t, dir, "vibes_en0_00001_20260731150000.pcap", 50) // older, pre-existing
	pathNewest := filepath.Join(dir, "vibes_en0_00002_20260731150100.pcap")
	fn, _ := os.Create(pathNewest)
	defer fn.Close()
	wn := pcapgo.NewWriter(fn)
	wn.WriteFileHeader(65536, layers.LinkTypeEthernet)
	appendTestPackets(t, fn, wn, 20) // pre-existing content in the newest file too

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	defer tl.Stop()
	time.Sleep(coldStartSettle)

	appendTestPackets(t, fn, wn, 7) // live traffic on the newest file

	got := collectPackets(tl.GetPacketChannel(), 7, 2*time.Second)
	if len(got) != 7 {
		t.Fatalf("got %d packets, want 7 live packets only", len(got))
	}

	// Let the newest file go quiet and confirm the tailer never falls back
	// to draining the older, pre-existing (50-packet) file.
	more := collectPackets(tl.GetPacketChannel(), 1, 500*time.Millisecond)
	if len(more) != 0 {
		t.Fatalf("tailer replayed the older pre-existing file: got unexpected extra packet")
	}
}

// --- Fix F5: fatal record errors must be logged once per file, not on
// every poll ---

// TestTailerLogsFatalRecordErrorOnceNotEveryPoll: a file whose only content
// (after a valid header) is a record with a corrupt/oversized length is the
// sole candidate the tailer can ever select, so it has nowhere to advance
// to and drain() will keep re-hitting the same fatal error every poll
// (~20ms in this test). That must produce exactly one log line, not one per
// poll.
func TestTailerLogsFatalRecordErrorOnceNotEveryPoll(t *testing.T) {
	dir := t.TempDir()
	path := writeTestPcap(t, dir, "vibes_en0_00001_20260731150000.pcap", 0)

	var buf syncStderr // reuse dumpcap_manager.go's concurrency-safe io.Writer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	tl := newTestTailer(dir)
	if err := tl.Start(); err != nil {
		t.Fatal(err)
	}
	// Let cold start (Finding F1) land at EOF of the header-only file first,
	// then append the corrupt record as "live" data — otherwise SeekToEnd
	// would land past it and the fatal condition would never trigger.
	time.Sleep(coldStartSettle)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:12], 0xFFFFFFFF) // corrupt/oversized incl_len
	if _, err := f.Write(rec); err != nil {
		t.Fatal(err)
	}
	f.Close()

	time.Sleep(400 * time.Millisecond) // ~20 poll cycles re-hitting the same corrupt record
	tl.Stop()
	time.Sleep(50 * time.Millisecond) // let any in-flight log call finish before reading

	count := strings.Count(buf.String(), "fatal error")
	if count != 1 {
		t.Fatalf("fatal error logged %d times over ~20 polls, want exactly 1 (F5: must not flood the log)", count)
	}
}
