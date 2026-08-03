# VIBES Network Visualizer Security & Bug Fixes Report

## 1. Executive Summary
This update addresses critical security vulnerabilities and functional bugs in the VIBES Network Visualizer. The focus was on preventing arbitrary file access, unauthorized port binding, and improving the robustness of IP pinning logic. Dependencies were also updated to mitigate known vulnerabilities.

## 2. Detailed Changelog

### Security Fixes
- **Path Traversal Mitigation**:
    - **Issue**: The `pcap` query parameter allowed reading any file on the system.
    - **Fix**: Implemented `filepath.Base()` sanitization and forced PCAP files to be read from the configured `-storage` directory.
    - **Impact**: Prevents attackers from reading sensitive system files.
- **Arbitrary Port Binding Prevention**:
    - **Issue**: The `zeek_tcp` query parameter allowed the server to bind to any port, including privileged ones.
    - **Fix**: Added validation to ensure the requested port is within the safe range (1024-65535).
    - **Impact**: Prevents DoS of other system services and port hijacking.
- **CORS Policy Implementation**:
    - **Issue**: `CheckOrigin` was returning `true` for all requests, allowing any website to connect to the WebSocket server.
    - **Fix**: Introduced the `-cors-origin` flag and updated `CheckOrigin` to validate the `Origin` header.
    - **Impact**: Reduces the risk of Cross-Site WebSocket Hijacking (CSWSH).

### Functional Improvements
- **Robust IP Range Parsing**:
    - **Issue**: `isIPPinned` only supported last-octet ranges (e.g., `1.10-20`) and failed on full IP ranges.
    - **Fix**: Rewrote the range parsing logic to support both shorthand (`1.10-20`) and full IP-to-IP ranges (`1.250-2.10`), utilizing `net.ParseIP` and `iplib.CompareIPs`.
    - **Impact**: Correctly handles pinning for networks that span multiple subnets or octets.

### Dependency Updates
- **Go Toolchain**: Updated from 1.21 to **1.23** to address multiple critical vulnerabilities in the standard library.
- **Node.js Dependencies**:
    - `ws` updated to `^8.21.0` in `backend/package.json`.
    - `lodash` updated to `^4.18.0` in `frontend/package.json`.
    - Transitive dependencies (like `@xmldom/xmldom`) resolved via updated version constraints.

## 3. Validation Report

### Test Case Outcomes
| Test Case | Input | Expected Result | Outcome |
| :--- | :--- | :--- | :--- |
| Path Traversal | `?pcap=/etc/passwd` | File not found or restricted to storage dir | **PASS** |
| Port Binding | `?zeek_tcp=:22` | 400 Bad Request | **PASS** |
| IP Pinning (Exact) | `192.168.1.1` | Pinned | **PASS** |
| IP Pinning (Shorthand) | `192.168.1.10-20` | 192.168.1.15 $\rightarrow$ Pinned | **PASS** |
| IP Pinning (Full Range) | `192.168.1.250-192.168.2.10` | 192.168.2.5 $\rightarrow$ Pinned | **PASS** |
| CORS Restriction | `-cors-origin example.com` | Request from `evil.com` rejected | **PASS** |

## 4. Risk Assessment Summary
- **Regressions**: Low. All changes were targeted and validated with unit tests.
- **Performance**: No measurable impact on packet processing throughput.
- **Availability**: High. Security restrictions are based on input validation and do not affect the core capture/replay loops.

## 5. Deployment Readiness
- **Build Status**: All Go tests passing.
- **Dependency Status**: Critical vulnerabilities mitigated.
- **Confirmation**: The codebase is **Ready for Deployment**.
