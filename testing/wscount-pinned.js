// Like wscount.js, but sends a "pinRule" for 0.0.0.0/0 immediately after
// connecting. VIBES's per-client forwarder (backend/cmd/main.go, the
// `manager.isIPPinned(...) || rand.Intn(10) < 9` line) randomly forwards
// only ~90% of packets to unpinned clients ("graph may sample" in the
// server log). Pinning the whole IPv4 space makes every packet's src/dst
// match a pin, so isIPPinned() short-circuits true and the random sample
// never applies — this is required for any e2e delivery-rate measurement,
// otherwise you measure the forwarder's sampling, not the capture path.
//
// Usage: node wscount-pinned.js <port> "<query>" <seconds>
//   e.g. node wscount-pinned.js 8082 "" 16
const port = process.argv[2] ?? '8080';
const params = process.argv[3] ?? '';
const seconds = Number(process.argv[4] ?? 8);
const url = `ws://localhost:${port}/ws` + (params ? `?${params}` : '');

const ws = new WebSocket(url);
let count = 0;
const srcs = new Set(), protos = new Map();
let sample = null;
ws.onopen = () => {
  ws.send(JSON.stringify({ type: 'pinRule', rule: '0.0.0.0/0' }));
};
ws.onerror = e => { console.error('WS ERROR:', e.message ?? e); process.exit(2); };
ws.onclose = e => { console.log('WS CLOSED early:', e.code, e.reason || ''); report(); };
ws.onmessage = m => {
  try {
    const d = JSON.parse(m.data);
    if (d.type === 'packet') {
      count++;
      srcs.add(d.src);
      protos.set(d.protocol, (protos.get(d.protocol) ?? 0) + 1);
      if (!sample) sample = d;
    }
  } catch {}
};
function report() {
  console.log(JSON.stringify({
    url, packets: count, uniqueSrcs: srcs.size,
    protocols: Object.fromEntries(protos), sample,
  }, null, 2));
  process.exit(0);
}
setTimeout(() => { try { ws.close(); } catch {} ; report(); }, seconds * 1000);
