# Dumpcap Capture Rewrite — Design

**Date:** 2026-07-31
**Status:** Approved direction, spec for implementation planning
**Goal:** Make dumpcap-based capture bulletproof: 100% raw packet capture to disk via dumpcap, with VIBES tailing those files losslessly for the live dashboard. Retained pcaps are the substrate for future replay/time-scrubbing.

## Why (audit findings, all reproduced 2026-07-31)

| # | Defect | Evidence |
|---|--------|----------|
| 1 | `checkDumpcapRunning` uses `pgrep -f dumpcap`, matches the backend's own argv (`-dumpcap`, `-launch-dumpcap`) → "already running" false positive, auto-launch never fires | Reproduced locally; sensor box history lines 599-615 show six failed `-launch-dumpcap` attempts at BH 2025 |
| 2 | `launchDumpcapProcess` discards stderr, never `Wait()`s → dumpcap dies silently (e.g. BPF permissions), app monitors an empty dir; zombie on exit | Reproduced: ChmodBPF missing on dev Mac, dumpcap exits instantly, app reports success |
| 3 | `readNewPackets` caps at 100 packets **per second** | Measured 84% loss at 500 pps (writer 6000, delivered 982) |
| 4 | Rotation switches to newest file by mtime without draining the previous file's tail | Code inspection; loss at every rotation boundary |
| 5 | Dumpcap packets not stamped with `Source` → arrive as `"simulated"` | Observed on websocket |
| 6 | If dumpcap-mode setup fails, client silently falls back to simulated traffic | Code inspection |

Validated as KEEP: dumpcap itself as the disk-writer. Sensor box ran `sudo dumpcap -i ens3np0 -P -B 1024 -w /raid0/...` through Black Hat 2025 with zero issues on 16×NVMe mdadm raid0 + XFS.

## Non-goals

- Replacing dumpcap with AF_PACKET/n2disk-style writers (proven unnecessary for our workload).
- Time-scrubber/replay UI (future; this design just guarantees the pcap ring exists for it).
- Zeek/pcap-replay/sim paths (audited healthy, unchanged).

## Architecture

Two units, cleanly separated:

### 1. `DumpcapManager` (new, backend/internal/capture/dumpcap_manager.go)

Owns the dumpcap **process** lifecycle. Only used with `-launch-dumpcap`; when the user runs dumpcap manually, the manager is not involved.

- **Preflight:** run `dumpcap -D` as capability probe. On failure return an actionable error (mentions ChmodBPF on darwin / setcap or sudo on linux). No launch attempt after failed preflight.
- **Launch args** (defaults mirror the proven BH invocation):
  `-i <iface> -P -B 1024 -w <dir>/vibes_<iface>.pcap -b filesize:<sizeKB> -b files:<N>`
  Ring defaults: 500 MB × 20 files (~10 GB bound, protects the OS drive); both flags exposed as `-dumpcap-filesize-mb`, `-dumpcap-ring-files`.
- **Supervision:** stderr piped into the app log with a `[dumpcap]` prefix; `cmd.Wait()` in a goroutine; on unexpected exit, log loudly and restart with exponential backoff (1s → 30s cap, reset after 60s healthy). On app shutdown, SIGTERM the child and wait briefly.
- **No pgrep.** We own what we launch. Without `-launch-dumpcap`, we monitor whatever files appear and never reason about processes.

### 2. `DumpcapCapture` tailer (rewrite of existing)

Owns **file discovery and lossless reading**. Works identically whether dumpcap was launched by the manager or manually.

- **File ordering:** ring files sorted by dumpcap's serial+timestamp naming (`_00001_20260731...`), falling back to mtime for non-ring names. Glob `*.pcap` and `*.pcapng`.
- **Drain-then-switch:** when a newer file appears, keep reading the current file until EOF is stable (two consecutive empty polls after the newer file exists), then switch. No tail loss at rotation.
- **No packet-count cap:** each poll drains until EOF with a time budget (~20 ms per cycle) so a burst can't starve the event loop but throughput is unbounded across cycles. Poll interval 250 ms.
- **EOF robustness:** if the pcap handle stops yielding while the file has grown (libpcap EOF latch), reopen the file and skip forward by packet count. Track `packetsRead` per file for the skip.
- **Labeling:** every packet stamped `Source: "dumpcap"`.
- **Failure is loud:** if dumpcap mode is requested and setup fails, the websocket client receives an error message; we never silently substitute simulated traffic.

### Data flow

```
dumpcap (child or manual) → ring files in -dumpcap-dir
DumpcapCapture tailer → packetChan → hub → websocket (rate limiting unchanged) → frontend
```

## Error handling

- Preflight failure → clear message, no capture, no sim fallback.
- Child death → logged with last stderr lines, backoff restart, status surfaced in `/api/status`.
- Unreadable/corrupt file → log, skip to next file (never spin on one file).
- Tailer falling behind (channel full) → drop counter logged once per 5s with totals, exposed in `/api/status`.

## Testing (all via existing testing/ harness patterns)

1. **Unit-ish:** `genpcap -tail` writer at 500, 2000, 5000 pps → websocket count must be ≥99% of written (vs 16% today). Rotation test: writer that rolls to a second file mid-stream; no gap in delivered packets.
2. **Launch failure path:** on the dev Mac (no ChmodBPF), `-launch-dumpcap` must produce the actionable error, not silence.
3. **Self-match regression:** backend started with `-dumpcap -launch-dumpcap` and no dumpcap installed/running must attempt launch (not claim "already running").
4. **Sensor validation (task #8):** the BH invocation via the manager on `10.220.199.71`, tailing from `/data/pcaps` at real tap rates.

## Deployment note (sensor box, separate task)

Same stack as BH 2025: mdadm raid0 (16× NVMe) + XFS, mounted at `/data`, world-readable, all capture writes on the array (never the OS NVMe). Zeek feeds the live dashboard via the TCP ingest; dumpcap ring on `/data/pcaps` is the deep-dive/replay archive.
