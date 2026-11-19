# intbug-lab ANOMALY / settings_iw_overflow FAIL triage

Date: 2026-11-19 America/Toronto  
Repo: https://github.com/c0re-i5/intbug-lab  
Matrix reviewed: `evidence/BATTERY-MATRIX-20261119-173219.txt` (one full `./scripts/run-all.sh` on `main` after the four expansion PRs, 12 targets, 7 probes; `BATTERY-MATRIX-latest.txt` is a copy).  
Sources: `evidence/MANUAL-REVIEW-NOTES.txt`, per-target transcripts listed below, classifier in `ours/battery.py`, zero-WU cross-check in `evidence/zero-wu/CROSSCHECK.md`.  
Scope: hand review of ANOMALY cells and `settings_iw_overflow` FAIL cells (22 cells), plus the nginx-family overflow FAILs (4 cells). **No novel CVE claims.** Verdicts are the author's hand-review judgment, not a proof.

Verdict key:

| Verdict | Meaning |
|---------|---------|
| **IGNORE** | Rejection (or known probe/harness quirk) understood; common stream-scoped style; h2spec already green where checked; do not spend more cycles unless hunting pure RFC pedantry. |
| **WATCH** | Opaque or harness-limited; keep on the matrix; optional follow-up listed; still **not** a CVE path. |
| **DIG** | Worth a short focused framing session because silent acceptance (or near-acceptance) is still unexplained at the conformance layer — still **not** a CVE claim unless accounting/`cleanup_overcredit` later lights up. |

---

## How the classifier decides (mechanics)

From `ours/battery.py` / `ours/oracle.py`:

| Probe | Strict PASS | ANOMALY | FAIL |
|-------|-------------|---------|------|
| `wu_zero_conn` | GOAWAY `PROTOCOL_ERROR` (1) | hard close w/ no GOAWAY, or unclear | stayed up + answered PING after WU(0)=0 |
| `wu_zero_stream` | GOAWAY `PROTOCOL_ERROR` | hard close w/ no GOAWAY **or** RST_STREAM only (conn kept). Stream opened **without** END_STREAM (h2spec `http2/6.9/2`) | stayed up + PING after zero stream WU |
| `wu_conn_overflow` | GOAWAY `FLOW_CONTROL_ERROR` (3) | closed-ish without that GOAWAY | stayed up + PING after overflow WU |
| `wu_stream_overflow` | GOAWAY `FLOW_CONTROL_ERROR` | RST_STREAM FC on stream (conn kept) **or** unclear hard close | stayed up + PING after MAX→MAX+1 stream WU |
| `settings_iw_overflow` | GOAWAY `FLOW_CONTROL_ERROR` | stream RST FC (conn kept) **or** mixed/unclear | alive + PING + **no** RST/GOAWAY (“appeared accepted”) |
| `cleanup_overcredit` | (separate) NOT_PROVEN vs accounting signal | — | nginx-class over-credit signature |

**Important:** ANOMALY ≠ vulnerability. FAIL on overflow probes ≠ CVE-2026-123007 discriminator (that discriminator is `cleanup_overcredit` alone). Prior widen-slice FAILs on `wu_zero_stream` for Apache/Envoy/nghttpd were **withdrawn** as a probe artifact (WU after END_STREAM).

---

## Pattern buckets (same reaction, many targets)

### Bucket A — stream RST, connection kept
Illegal stream-level WU / SETTINGS overflow is rejected with `RST_STREAM`, connection stays up. RFC 9113 §6.9.x wants a **connection** error (GOAWAY). h2spec still passes the zero-WU cases.

Seen on: Caddy, Go `net/http`, httpd (overflow), nghttpd (overflow), HAProxy, OpenLiteSpeed.

### Bucket B — hard close, no GOAWAY
Peer drops TLS/TCP with no GOAWAY and often no RST. Illegal frame is not “accepted,” but the rejection style is opaque.

Seen on: Envoy (conn + stream probes); Node `http2` (stream / overflow / settings).

### Bucket C — harness / early-completion FAIL on `settings_iw_overflow`
Probe flight is: SETTINGS IW=0 → GET **with END_STREAM** → WU(MAX−1) → SETTINGS IW=2. If the static body is ≤ remaining credit, the handler can finish the stream in the same flight before an overflow is forced. Score becomes FAIL (“appeared accepted”) even when connection-level probes PASS.

Seen on: HAProxy (`http-request return file`), OpenLiteSpeed (896-byte static), and noted as a caveat for similar static/direct_response frontends.

### Bucket D — nginx-family overflow FAILs on both vuln and patched
`wu_stream_overflow` / `settings_iw_overflow` FAIL on nginx 1.31.8 **and** 1.31.9 (and OpenResty 1.31.8.1). Not a CVE-2026-123007 discriminator.

---

## Per-cell triage

### Expanded targets (this week)

| Target | Probe | Battery score | What probe expected | What server did | Benign? | Verdict |
|--------|-------|---------------|---------------------|-----------------|---------|---------|
| **node-http2** | `wu_zero_stream` | ANOMALY | GOAWAY PROTOCOL_ERROR | `alive=False`, `goaway=None`, `rst=[]` — hard close | Likely yes (Bucket B; conn-level `wu_zero_conn` **PASS**ed with GOAWAY) | **WATCH** |
| **node-http2** | `wu_stream_overflow` | ANOMALY | GOAWAY FLOW_CONTROL_ERROR | `alive=False`, `goaway=None` — unclear hard close | Likely yes (Bucket B) | **WATCH** |
| **node-http2** | `settings_iw_overflow` | ANOMALY | GOAWAY FLOW_CONTROL_ERROR | `alive=False`, `goaway=None`, `rst={}` — hard close (not the “accepted” FAIL path) | Likely yes (Bucket B) | **WATCH** |
| **haproxy-3.0** | `wu_zero_stream` | ANOMALY | GOAWAY PROTOCOL_ERROR | `RST_STREAM` error=1 on stream 1, `alive=True` | Yes (Bucket A; same as Caddy/Go; h2spec class) | **IGNORE** |
| **haproxy-3.0** | `wu_stream_overflow` | ANOMALY | GOAWAY FLOW_CONTROL_ERROR | RST_STREAM FLOW_CONTROL_ERROR, conn kept | Yes (Bucket A) | **IGNORE** |
| **haproxy-3.0** | `settings_iw_overflow` | **FAIL** | GOAWAY FLOW_CONTROL_ERROR | `alive=True`, no RST/GOAWAY, PING answered | **Harness-suspect** (Bucket C): return-file ignores Range; END_STREAM request + full 896-byte answer in-flight | **WATCH** |
| **openlitespeed-1.9.4** | `wu_zero_stream` | ANOMALY | GOAWAY PROTOCOL_ERROR | RST PROTOCOL_ERROR stream 1, conn kept | Yes (Bucket A) | **IGNORE** |
| **openlitespeed-1.9.4** | `wu_stream_overflow` | ANOMALY | GOAWAY FLOW_CONTROL_ERROR | RST FLOW_CONTROL_ERROR, conn kept | Yes (Bucket A) | **IGNORE** |
| **openlitespeed-1.9.4** | `settings_iw_overflow` | **FAIL** | GOAWAY FLOW_CONTROL_ERROR | `alive=True`, no RST/GOAWAY, PING answered | **Harness-suspect** (Bucket C): WU(MAX−1) covers 896-byte body; static can finish same flight | **WATCH** |

Notes for expanded targets:

- Node / HAProxy / OLS: `cleanup_overcredit` = **PASS** (soft profile). No accounting signature. Not CVE material.
- HAProxy Range smoke was HTTP/2 200 full body (not 206) — reinforces Bucket C for settings FAIL.
- OLS Range smoke was HTTP/2 206 — Range works; settings FAIL is still early-completion / scoring, not an accounting bug.
- OLS WebAdmin 7080 not published — out of scope for this triage.

### Prior matrix (Envoy / Caddy / Go / httpd / nghttpd / nginx family)

| Target | Probe | Battery score | What server did | Verdict |
|--------|-------|---------------|-----------------|---------|
| **caddy-2.10** | `wu_zero_stream` | ANOMALY | RST PROTOCOL_ERROR, conn kept; framing capture confirms; h2spec ✔ | **IGNORE** |
| **caddy-2.10** | `wu_stream_overflow` | ANOMALY | RST FLOW_CONTROL_ERROR, conn kept | **IGNORE** |
| **go-nethttp** | `wu_zero_stream` | ANOMALY | RST PROTOCOL_ERROR, conn kept; h2spec ✔ | **IGNORE** |
| **go-nethttp** | `wu_stream_overflow` | ANOMALY | RST FLOW_CONTROL_ERROR, conn kept | **IGNORE** |
| **envoy-1.32** | `wu_zero_conn` | ANOMALY | hard close, no GOAWAY | **WATCH** |
| **envoy-1.32** | `wu_zero_stream` | ANOMALY (post open-stream fix) | hard close, no GOAWAY; framing capture confirms; h2spec ✔ | **WATCH** |
| **envoy-1.32** | `wu_conn_overflow` | ANOMALY | hard close, no GOAWAY FC | **WATCH** |
| **envoy-1.32** | `wu_stream_overflow` | ANOMALY | hard close unclear | **WATCH** |
| **envoy-1.32** | `settings_iw_overflow` | ANOMALY | RST FLOW_CONTROL_ERROR stream 1, conn kept (`rst={1:3}`) | **IGNORE** |
| **httpd-2.4.71** | `wu_stream_overflow` | ANOMALY | RST FLOW_CONTROL_ERROR, conn kept | **IGNORE** |
| **httpd-2.4.71** | `settings_iw_overflow` | ANOMALY | RST FLOW_CONTROL_ERROR, conn kept | **IGNORE** |
| **nghttpd** | `wu_stream_overflow` | ANOMALY | RST FLOW_CONTROL_ERROR, conn kept | **IGNORE** |
| **nghttpd** | `settings_iw_overflow` | ANOMALY | RST FLOW_CONTROL_ERROR, conn kept | **IGNORE** |
| **nginx-1.31.8 / 1.31.9** | `wu_stream_overflow` | **FAIL** | stayed up / PING after open-stream MAX→MAX+1 | **DIG**† |
| **nginx-1.31.8 / 1.31.9** | `settings_iw_overflow` | **FAIL** | stayed up / PING, no RST/GOAWAY | **DIG**† |
| **openresty-1.31.8.1** | `wu_stream_overflow` | **FAIL** | same nginx-family shape | **DIG**† |
| **openresty-1.31.8.1** | `settings_iw_overflow` | **FAIL** | same nginx-family shape | **DIG**† |

† **DIG means conformance dig only.** Present on **both** vulnerable and patched nginx, and on OpenResty which **PASS**ed `cleanup_overcredit`. Explicitly **not** a CVE-2026-123007 claim and **not** a novel-CVE claim. Suggested dig: h2spec §6.9.1 / §6.9.2 overflow cases + one framing capture of the exact MAX→MAX+1 flight, document whether nginx clamps, ignores, or really accepts the overflow. Stop after that write-up unless something new appears.

Envoy `direct_response` Range limitation (note 8 in MANUAL-REVIEW-NOTES) remains a lab limitation, not an Envoy bug claim — **IGNORE** as a finding.

---

## Transcript / evidence pointers

| Target | Transcript / note |
|--------|-------------------|
| node-http2 | `evidence/BATTERY-node-http2-20261119-173219.txt` (earlier: `-165746`); MANUAL notes §12–13 |
| haproxy-3.0 | `evidence/BATTERY-haproxy-3.0-20261119-173219.txt` (earlier: `-170604`); MANUAL notes §14–18 |
| openlitespeed-1.9.4 | `evidence/BATTERY-openlitespeed-1.9.4-20261119-173219.txt` (earlier: `-171550`); MANUAL notes §19–24 |
| openresty | `evidence/BATTERY-openresty-1.31.8.1-20261119-173219.txt` (earlier: `-164827`, `-164916`); MANUAL notes §10–11 |
| caddy / go / envoy (post-fix) | `evidence/BATTERY-*-20261119-000332.txt`; zero-WU captures under `evidence/zero-wu/` |
| matrix snapshot | `evidence/BATTERY-MATRIX-20261119-173219.txt` (single full run; `BATTERY-MATRIX-latest.txt` is a copy) |
| classifier | `ours/battery.py` (`probe_wu_zero_stream`, `probe_wu_stream_overflow`, `probe_settings_iw_overflow`) |

---

## Recommended next actions (ordered, still no CVE claims)

1. **Do nothing** on Bucket A (Caddy/Go/HAProxy/OLS/httpd/nghttpd stream-RST ANOMALYs) — document as “stream-scoped rejection; RFC prefers GOAWAY; h2spec OK.”
2. **Optional WATCH follow-ups** (only if expanding the lab’s honesty, not hunting CVEs):
   - HAProxy: tiny loopback HTTP sidecar behind HAProxy so Range + real stream lifecycle exist; re-run `settings_iw_overflow` and soft `cleanup_overcredit`.
   - OLS / static targets: re-flight `settings_iw_overflow` with open stream (no END_STREAM) or a body larger than MAX−1 credit so early completion cannot mask the SETTINGS delta.
   - Node / Envoy: one framing capture each for `wu_stream_overflow` / `settings_iw_overflow` hard closes (mirror `evidence/zero-wu/`) so the matrix notes stop saying “unclear.”
3. **Only DIG:** nginx-family `wu_stream_overflow` + `settings_iw_overflow` FAILs — conformance cross-check with h2spec + framing dump; expect “known nginx behavior on both builds,” not a new bug class.
4. **Do not** treat any of the above as coordinated-disclosure candidates unless `cleanup_overcredit` (or a new accounting probe) later FAILs on a stack that is not already the known nginx CVE line.

---

## Summary counts

| Verdict | Count (cells in this triage) |
|---------|------------------------------|
| IGNORE | 13 |
| WATCH | 9 |
| DIG | 4 (two probes × nginx-family: nginx 1.31.8/1.31.9 rows and OpenResty rows; one conformance dig covers them) |

**Bottom line:** Almost everything that was labeled ANOMALY is either (A) stream-scoped RST that h2spec already accepts, or (B) hard-close hygiene. The scary-looking `settings_iw_overflow` FAILs on HAProxy and OpenLiteSpeed are most likely **probe/harness early-completion**, not silent overflow bugs. The only cells worth a real dig are the **nginx-family overflow FAILs**, and only as RFC-conformance documentation — they are already known to fire on both vulnerable and patched nginx and are **not** the bug-class discriminator.
