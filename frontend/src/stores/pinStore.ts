import { create } from 'zustand';
import { persist, PersistStorage } from 'zustand/middleware';

// ---------------------------------------------------------------------------
// Compiled matcher (module-level, shared across all isPined calls).
//
// isPined() runs in the physics/render hot path — once per node AND once per
// edge endpoint, every frame. The old implementation allocated two Address4
// objects and did BigInt subnet math on every call, so pinning a /24 with
// hundreds of nodes and thousands of edges melted the render loop.
//
// Instead we compile the rule set ONCE into plain uint32 masks/ranges and an
// exact-match Set, then match with branch-cheap integer ops and memoize the
// result per IP. Warm path is a single Map lookup; cold path is a handful of
// integer comparisons. No allocations, no BigInt.
// ---------------------------------------------------------------------------

let ruleVersion = 0;        // bumped on every rule mutation / rehydrate
let compiledVersion = -1;   // version the compiled state below reflects
let exactSet = new Set<string>();
let cidrs: { net: number; mask: number }[] = [];
let ranges: { start: number; end: number }[] = [];
let memo = new Map<string, boolean>();

// Parse a dotted-quad to a uint32, or null if malformed.
function ipToUint(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (let i = 0; i < 4; i++) {
    const octet = Number(parts[i]);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    n = n * 256 + octet;
  }
  return n >>> 0;
}

function compile(rules: Set<string>) {
  const nextExact = new Set<string>();
  const nextCidrs: { net: number; mask: number }[] = [];
  const nextRanges: { start: number; end: number }[] = [];

  for (const rule of rules) {
    const slash = rule.indexOf('/');
    if (slash > 0) {
      // CIDR: a.b.c.d/bits
      const base = ipToUint(rule.slice(0, slash));
      const bits = Number(rule.slice(slash + 1));
      if (base !== null && Number.isInteger(bits) && bits >= 0 && bits <= 32) {
        const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
        nextCidrs.push({ net: (base & mask) >>> 0, mask });
        continue;
      }
    }

    const dash = rule.indexOf('-');
    if (dash > 0 && slash < 0) {
      // Range: a.b.c.d-e (last octet range)
      const startStr = rule.slice(0, dash);
      const endOctet = Number(rule.slice(dash + 1));
      const startN = ipToUint(startStr);
      const lastDot = startStr.lastIndexOf('.');
      if (startN !== null && lastDot > 0 && Number.isInteger(endOctet) && endOctet >= 0 && endOctet <= 255) {
        const endN = ipToUint(startStr.slice(0, lastDot + 1) + endOctet);
        if (endN !== null) {
          nextRanges.push({ start: Math.min(startN, endN), end: Math.max(startN, endN) });
          continue;
        }
      }
    }

    // Fallback: exact IP (or anything we couldn't parse — matched literally).
    nextExact.add(rule);
  }

  exactSet = nextExact;
  cidrs = nextCidrs;
  ranges = nextRanges;
  memo = new Map();
  compiledVersion = ruleVersion;
}

function matches(ip: string): boolean {
  if (exactSet.has(ip)) return true;
  const n = ipToUint(ip);
  if (n === null) return false;
  for (let i = 0; i < cidrs.length; i++) {
    if (((n & cidrs[i].mask) >>> 0) === cidrs[i].net) return true;
  }
  for (let i = 0; i < ranges.length; i++) {
    if (n >= ranges[i].start && n <= ranges[i].end) return true;
  }
  return false;
}

// Helper retained for external callers that validate CIDR input.
export function isCIDR(value: string): boolean {
  const slash = value.indexOf('/');
  if (slash <= 0) return false;
  const base = ipToUint(value.slice(0, slash));
  const bits = Number(value.slice(slash + 1));
  return base !== null && Number.isInteger(bits) && bits > 0 && bits <= 32;
}

interface PinState {
  pinningRules: Set<string>;
  addPinningRule: (rule: string) => void;
  removePinningRule: (rule: string) => void;
  clearAllPins: () => void;
  isPined: (ip: string) => boolean;
}

const storage: PersistStorage<PinState> = {
  getItem: (name) => {
    const str = localStorage.getItem(name);
    if (!str) return null;
    const { state } = JSON.parse(str);
    return {
      state: {
        ...state,
        pinningRules: new Set(state.pinningRules),
      },
    };
  },
  setItem: (name, newValue) => {
    const str = JSON.stringify({
      state: {
        ...newValue.state,
        pinningRules: Array.from(newValue.state.pinningRules),
      },
    });
    localStorage.setItem(name, str);
  },
  removeItem: (name) => localStorage.removeItem(name),
};

export const usePinStore = create<PinState>()(
  persist(
    (set, get) => ({
      pinningRules: new Set(),
      addPinningRule: (rule) => {
        ruleVersion++;
        set((state) => {
          const newRules = new Set(state.pinningRules);
          newRules.add(rule);
          return { pinningRules: newRules };
        });
      },
      removePinningRule: (rule) => {
        ruleVersion++;
        set((state) => {
          const newRules = new Set(state.pinningRules);
          newRules.delete(rule);
          return { pinningRules: newRules };
        });
      },
      clearAllPins: () => {
        ruleVersion++;
        set({ pinningRules: new Set() });
      },
      isPined: (ip) => {
        if (compiledVersion !== ruleVersion) compile(get().pinningRules);
        const cached = memo.get(ip);
        if (cached !== undefined) return cached;
        const result = matches(ip);
        memo.set(ip, result);
        return result;
      },
    }),
    {
      name: 'pin-storage',
      storage: storage,
      // Rehydration replaces pinningRules without going through the setters,
      // so force a recompile on the next isPined call.
      onRehydrateStorage: () => () => {
        ruleVersion++;
      },
    }
  )
);
