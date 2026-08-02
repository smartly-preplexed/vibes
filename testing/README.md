# VIBES testing harness (local, gitignored)

Headless-browser verification scripts for the layout engine. These drive the
real app and measure it — run them before claiming any layout change works.

## Setup (once, or after node_modules is wiped)

```bash
cd testing
npm install            # installs playwright (see package.json)
npx playwright install chromium
```

Both servers must be running first:

```bash
cd backend  && go run ./cmd &          # :8080, simulated traffic
cd frontend && npm run dev &           # :5173
```

## Scripts

| Script | What it does | Pass criteria |
|---|---|---|
| `check.js` | Screenshots at default (150) and 1000 nodes + FPS + page errors | eyeball + FPS ≥ ~40 headless |
| `stability.js` | Samples layout twice, 4s apart: node churn, displacement, edge churn | node churn <25%, connected drift <40px, ≥15 connected nodes (exit code) |
| `monitor.js` | Polls store/layout counts at 100ms for 30s, flags prune cliffs | layoutEdges deltas should stay within ±2 |
| `blobtrace.js` | Traces blob centroids + center-of-mass + mean vx over 10s at 1000 nodes | COM stationary, per-blob vx ≈ 0 |
| `burst.js` | 10 screenshots at 700ms intervals (flicker/teleport check) | frames should look near-identical |

All screenshots land in this directory (gitignored).

These rely on dev-only globals exposed by `useGraphLayout.ts`:
`window.__VIBES_LAYOUT`, `window.__VIBES_STORE`, `window.__VIBES_SETTINGS`.

## Dumpcap e2e

Verifies the `DumpcapTailer` capture path (`backend/internal/capture/dumpcap_*.go`):
lossless throughput at high pps, gap-free ring-file rotation, and a loud
synchronous failure (not a silent fallback or background crash-loop) when
`-launch-dumpcap` can't actually capture. Reference run: 2026-07-31,
`.superpowers/sdd/2026-07-31-dumpcap-capture-rewrite/task-7-report.md`.

Tools used, in addition to the scripts above:
- `gotools/genpcap` — synthetic pcap writer. Static: `go run ./genpcap <out.pcap> <n>`.
  Live-writer simulation: `go run ./genpcap -tail <out.pcap> <batches> <perBatch> <intervalMs>`
  (appends `batches` batches of `perBatch` packets, `intervalMs` apart — classic pcap,
  `LinkTypeEthernet`, compatible with the tailer).
- `wscount-pinned.js` — like `wscount.js`, but sends `{"type":"pinRule","rule":"0.0.0.0/0"}`
  right after connecting and takes the port as an explicit argument:
  `node wscount-pinned.js <port> "<query>" <seconds>`.

**Read this before measuring delivery %:** `backend/cmd/main.go`'s per-client packet
forwarder randomly forwards only ~90% of packets to a client with no pinning rules
(`manager.isIPPinned(...) || rand.Intn(10) < 9`) — this is a UI-load sampler, not a
capture-path limiter, but it silently caps any naive throughput measurement at ~90%
regardless of how well the tailer performs. `wscount-pinned.js` pins `0.0.0.0/0` so
every packet's src/dst matches a pin and the random sample never applies. Always use
`wscount-pinned.js` (not plain `wscount.js`) for these three checks, or the numbers
below are meaningless.

Ring-file names must match `_(\d{5})_\d{8,14}\.(pcap|pcapng)$` (5-digit serial,
8-14 digit timestamp) for serial-based ordering to engage — e.g.
`vibes_e2e_00001_20260731173648.pcap`. `testing/pcaps/` should contain no other
`.pcap` files while running these (an unrelated file present alongside the ring
files can get picked up as "latest" first and pollute the count) — stash or
delete stray pcaps before starting.

### 1. Throughput — must beat the old 100 pps / 16%-at-500pps cap

```bash
# backend in dumpcap MONITOR mode (no -launch-dumpcap: just tails the dir), sampling irrelevant here
# since we pin — no rate-limit flags exist/need disabling in this codebase.
cd backend && go run ./cmd -addr :8082 -dumpcap -dumpcap-dir "$PWD/../testing/pcaps" &
sleep 3

cd testing
TS=$(date +%Y%m%d%H%M%S)
node wscount-pinned.js 8082 "" 18 > count.json &
sleep 1
cd gotools && go run ./genpcap -tail "$PWD/../pcaps/vibes_e2e_00001_${TS}.pcap" 10 2000 1000
# 10 batches x 2000 pkts/batch x 1000ms interval = 20,000 packets over ~10s at 2000 pps
wait
cat ../count.json
```

Pass: `packets` >= 19800 (>=99% of 20000). Reference run delivered **20000/20000
(100%)**. Clean up the test pcap after (`rm testing/pcaps/vibes_e2e_00001_*.pcap`),
then stop the :8082 backend (`lsof -ti:8082 -sTCP:LISTEN | xargs kill`).

### 2. Rotation — gap-free switch across ring files

Same backend (or restart it as above). Write two serial files back-to-back and
confirm the delivered total is the sum of both, with the tailer log showing a
clean switch (no error/gap lines) between them:

```bash
cd testing
node wscount-pinned.js 8082 "" 16 > count.json &
sleep 1
cd gotools
TS1=$(date +%Y%m%d%H%M%S)
go run ./genpcap -tail "$PWD/../pcaps/vibes_rot_00001_${TS1}.pcap" 5 500 1000   # 2500 pkts, ~5s
TS2=$(date +%Y%m%d%H%M%S)
go run ./genpcap -tail "$PWD/../pcaps/vibes_rot_00002_${TS2}.pcap" 5 500 1000   # 2500 pkts, ~5s
wait
cat ../count.json
```

Pass: `packets` >= 4950 (>=99% of 5000 = 2x 2500). Reference run delivered
**5000/5000 (100%)**; backend log showed
`📂 dumpcap tailer: reading .../vibes_rot_00001_...pcap` immediately followed
by `📂 dumpcap tailer: reading .../vibes_rot_00002_...pcap` with no error lines
between them. Clean up (`rm testing/pcaps/vibes_rot_*.pcap`) and stop the backend.

### 3. Launch-failure — must fail loudly and exit, not silently degrade

On a Mac without ChmodBPF installed (or any host where the invoking user can't
open `/dev/bpf*`), `-launch-dumpcap` must make the process exit non-zero
immediately with an actionable message — not start serving while the dumpcap
child crash-loops in the background, and not silently fall back to another
capture mode:

```bash
cd backend && go run ./cmd -addr :8086 -dumpcap -launch-dumpcap -iface en0 -dumpcap-dir /tmp/vibes-launch-test
echo "EXIT_CODE=$?"
```

Pass: exits with a nonzero code and a `❌ dumpcap launch failed: dumpcap
preflight failed: ...` message that includes ChmodBPF/permission guidance.
Reference run: exited with `EXIT_CODE=1` and printed the full ChmodBPF advice
(the real macOS `dumpcap` permission-denied stderr, wrapped by
`DumpcapManager.Preflight()`'s platform-specific advice text). If it does
*not* fail on your run — e.g. you do have capture permission, or you're on a
host where preflight passes — that's not this check failing, it means
preflight correctly detected working permissions; rerun on a host that lacks
them to exercise the failure path.
