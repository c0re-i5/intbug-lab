# HTTP/2 Flow-Control Integer-Bug Lab

**A reproducible lab that detects the HTTP/2 flow-control integer-bug class (CWE-191) and validates it against nginx CVE-2026-123007 across twelve loopback servers.**

*Research write-up — 2026-11-19 (America/Toronto)*

---

## Summary

This project is a standalone, one-command lab for the **class** of HTTP/2 flow-control / counter / length integer bugs. It runs a seven-probe invariant battery against twelve loopback targets and **reliably distinguishes** the known nginx CVE-2026-123007 accounting bug from patched nginx and from every other stack under test.

On nginx 1.31.8 (known-vulnerable), the `cleanup_overcredit` probe fails. On nginx 1.31.9 (patched) and on Apache, Caddy, Envoy, Go `net/http`, nghttpd, OpenResty 1.31.8.1, Node.js stdlib `http2`, HAProxy 3.0.31, and OpenLiteSpeed 1.9.4 Open, the same probe passes. The nginx pair matches arkrwn's public `--safe` PoC on the same listeners. OpenResty 1.31.8.1 is still the nginx 1.31.8 line and was run at full KeyUpdate pressure; the accounting signal was not observed. Node, HAProxy, and OpenLiteSpeed were run on the soft profile (`key_updates=0`, `carrier=200000`), same as Go and Caddy. Those PASSes are not a new CVE, and the OpenResty PASS is not a claim that this build contains the nginx fix. HAProxy answers from `http-request return file` and ignores Range. OpenLiteSpeed here is the open-source server, not commercial LSWS Enterprise, and its static files do implement Range. The method is target-agnostic; adding a server is a few lines in `ours/targets.py`.

No new vulnerability is reported from this work. The deliverable is a **working, validated method** — not a one-CVE detector that expires when nginx is patched.

| | |
|---|---|
| Targets | 12 loopback servers |
| Probes | 7 RFC 9113 invariants |
| Offline tests | 28 |
| CVE-class discriminator | `cleanup_overcredit` |

---

## Motivation

CVE-2026-123007 (nginx2root) is an unauthenticated HTTP/2 flow-control integer underflow (CWE-191) in nginx since 1.9.5. Public research from Rapid7 and arkrwn established the bug and a safe accounting proof. A detector keyed to that single CVE goes stale the day the patch ships.

A durable alternative is to encode the **protocol invariant**, drive peers to the accounting edge that would break it, and score the outcome across implementations. When the next server mishandles a counter the way nginx did, the same battery is already pointed at it.

---

## Method

Three components:

1. **Framing / driver** (`ours/framing.py`, `ours/driver.py`) — raw HTTP/2 encoder that can emit adversarial `WINDOW_UPDATE` values, plus a counter-driver that exhausts the initial 65,535-byte connection window with public bodies, queues DATA under TCP backpressure, refunds via cleanup, and tests whether a post-refund `WINDOW_UPDATE(MAX)` is accepted (the underflowed-guard failure). Traffic is ~7–15 MiB (carrier + optional TLS KeyUpdates).
2. **Oracle** (`ours/oracle.py`) — status vocabulary: `PASS`, `FAIL`, `ANOMALY`, `INCONCLUSIVE`, `SKIP`, `ERROR`. Incomplete transport deaths are `INCONCLUSIVE`.
3. **Battery** (`ours/battery.py` + `ours/targets.py`) — seven RFC 9113–cited probes on an extensible target registry.

### Invariant probes

| Probe | Checks | RFC |
|-------|--------|-----|
| `h2_alpn` | ALPN `h2` present/absent as expected | §3.3 / RFC 7301 |
| `wu_zero_conn` | Connection `WINDOW_UPDATE` increment 0 → `PROTOCOL_ERROR` | §6.9.1 |
| `wu_zero_stream` | Stream `WINDOW_UPDATE` increment 0 → `PROTOCOL_ERROR` | §6.9.1 |
| `wu_conn_overflow` | Connection WU past `MAX=2^31-1` → `FLOW_CONTROL_ERROR` | §6.9.1 |
| `wu_stream_overflow` | Stream WU past MAX → `FLOW_CONTROL_ERROR` | §6.9.1 |
| `settings_iw_overflow` | `SETTINGS_INITIAL_WINDOW_SIZE` delta past MAX | §6.9.2 |
| `cleanup_overcredit` | Queued-DATA cleanup must not push the connection window above MAX; post-refund WU guard (CVE-2026-123007 accounting class) | §6.9 / CWE-191 |

`cleanup_overcredit` is the CVE-class discriminator.

### Targets

| id | Role | Listen | Pin |
|----|------|--------|-----|
| `nginx-1.31.8` | known-vulnerable | `127.0.0.1:19443` | `nginx@sha256:5ab5b0b0…` |
| `nginx-http2-off` | negative control (`http2` off) | `127.0.0.1:19444` | same image |
| `httpd-2.4.71` | Apache + mod_http2 | `127.0.0.1:19445` | `httpd@sha256:32e94033…` |
| `nginx-1.31.9` | patched control | `127.0.0.1:19446` | `nginx@sha256:08f354a3…` |
| `caddy-2.10` | Caddy | `127.0.0.1:19447` | `caddy@sha256:c3d7ee5d…` |
| `envoy-1.32` | Envoy | `127.0.0.1:19448` | `envoyproxy/envoy@sha256:6bf0d37d…` |
| `go-nethttp` | Go `net/http` | `127.0.0.1:19449` | built from `golang@sha256:1a6d4452…` |
| `nghttpd` | nghttp2 reference | `127.0.0.1:19450` | pinned `debian` base; apt `nghttp2-server` floats |
| `openlitespeed-1.9.4` | OpenLiteSpeed 1.9.4 Open (not LSWS Enterprise) | `127.0.0.1:19451` | `litespeedtech/openlitespeed@sha256:48bc2719f2…` (`:1.9.4-lsphp82`) |
| `openresty-1.31.8.1` | nginx-family (OpenResty, nginx 1.31.8 line) | `127.0.0.1:19452` | `openresty/openresty@sha256:2cb90d6419…` |
| `haproxy-3.0` | HAProxy 3.0.31 LTS, `http-request return` | `127.0.0.1:19453` | `haproxy@sha256:7430e63d30…` (`:3.0-alpine` → 3.0.31) |
| `node-http2` | Node.js stdlib `http2` | `127.0.0.1:19454` | built from `node@sha256:1314fb30ec…` (`:22-alpine` → v22.23.5) |

Bodies: 896-byte `/index.html` (Range-capable where supported).

OpenResty 1.31.8.1 (`:alpine`) is still the nginx 1.31.8 line, so it is not an independent implementation. The lab runs it under the same full KeyUpdate pressure as nginx 1.31.8. A `cleanup_overcredit` FAIL on that listener is nginx-family inheritance of CVE-2026-123007, not a new CVE. Point follow-up at the nginx vendor advisory and re-pin when OpenResty ships 1.31.9+ or a backport. The alpine image has no `openssl` CLI; the entrypoint installs that package only to mint the lab certificate.

Node.js `http2` is stdlib-only on a pinned `node:22-alpine` base (v22.23.5). Certs are the lab pair mounted at `/certs`, same as Caddy and Envoy. The server handles a single `Range` so the cleanup fill/canary path can run. It is published only on `127.0.0.1:19454`. The base digest is pinned; `server.js` is not separately hashed. The registered cleanup profile is the soft one.

HAProxy 3.0.31 is one container on `127.0.0.1:19453`. TLS and ALPN `h2` are on the frontend, and `/` plus `/index.html` are served with `http-request return file` (no second backend). The entrypoint concatenates the lab cert and key into one PEM. The image user is `haproxy`; the lab entrypoint runs as root only so it can write that PEM. The publish stays loopback. HAProxy 3.0.31 does not accept a trailing backslash as a line continuation, so the return rule is a single line. `return file` ignores Range (smoke: HTTP/2 200, 896 bytes for `Range: bytes=0-9`). The registered cleanup profile is the soft one. Traefik was not selected.

OpenLiteSpeed 1.9.4 Open is one container on `127.0.0.1:19451`. This is open-source OLS (`litespeedtech/openlitespeed`), not commercial LSWS Enterprise. The entrypoint copies the lab cert, sets `disableWebAdmin 1`, and points the HTTPS listener and the docker vhost at that cert with `enableSpdy 8`. WebAdmin 7080 is not published. The shared index is the docroot. Static Range works (smoke: HTTP/2 206, 10 bytes for `Range: bytes=0-9`). The lsphp image is heavy (unpacked about 726 MiB on this box). The registered cleanup profile is the soft one. The lab config is not separately hashed.

---

## Validation

Against arkrwn `--safe` on the same loopback listeners (2026-11-18, America/Toronto):

| Target | arkrwn `--safe` | This lab | Match |
|--------|-----------------|----------|-------|
| nginx 1.31.8 HTTP/2+TLS `:19443` | VULNERABLE (exit 0) | `cleanup_overcredit` **FAIL** | Yes |
| nginx 1.31.8, `http2` off `:19444` | NOT PROVEN (exit 4) | NOT PROVEN / `h2_alpn` only | Yes |

On the vulnerable build the oracle records RST `FLOW_CONTROL_ERROR` on the queued streams, canary byte release, post-refund PING ACK, and a still-usable connection — the accounting invariant breaking under controlled conditions. Patched nginx 1.31.9 and Apache httpd 2.4.71 complete the same probe under full KeyUpdate pressure (`key_updates=262144`, `carrier=7340032`) with **PASS**.

---

## Results

One full `./scripts/run-all.sh` on `main` (not `--skip-heavy`), 2026-11-19 America/Toronto, about 4 min 54 s: 12 targets up and smoked (all HTTP/2 200 except the `http2`-off negative control, which answers HTTP/1.1), 28 unit tests OK, harness exit 0, no `ERROR` cells. Every column below is from that one run (`evidence/BATTERY-MATRIX-20261119-173219.txt`; `BATTERY-MATRIX-latest.txt` is a copy). `—` = probe not applicable (HTTP/2 off).

| probe | nginx-1.31.8 | http2-off | httpd-2.4.71 | nginx-1.31.9 | caddy | envoy | go | nghttpd | openlitespeed-1.9.4 | openresty-1.31.8.1 | node-http2 | haproxy-3.0 |
|-------|--------------|-----------|--------------|--------------|-------|-------|----|---------|---------------------|--------------------|------------|-------------|
| `h2_alpn` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `wu_zero_conn` | PASS | — | PASS | PASS | PASS | ANOMALY | PASS | PASS | PASS | PASS | PASS | PASS |
| `wu_zero_stream` | PASS | — | PASS | PASS | ANOMALY | ANOMALY | ANOMALY | PASS | ANOMALY | PASS | ANOMALY | ANOMALY |
| `wu_conn_overflow` | PASS | — | PASS | PASS | PASS | ANOMALY | PASS | PASS | PASS | PASS | PASS | PASS |
| `wu_stream_overflow` | FAIL | — | ANOMALY | FAIL | ANOMALY | ANOMALY | ANOMALY | ANOMALY | ANOMALY | FAIL | ANOMALY | ANOMALY |
| `settings_iw_overflow` | FAIL | — | ANOMALY | FAIL | PASS | ANOMALY | PASS | ANOMALY | FAIL | FAIL | ANOMALY | FAIL |
| `cleanup_overcredit` | **FAIL** | — | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

**Reading the matrix**

- **Headline:** `cleanup_overcredit` FAILs on nginx 1.31.8 only and PASSes on the 10 other HTTP/2 stacks. `nginx-http2-off` is the negative control: same image as 1.31.8 with `http2` disabled, so the HTTP/2 probes are not applicable.
- `cleanup_overcredit` is the CVE-class discriminator: FAIL on nginx 1.31.8; PASS on patched nginx and every other h2 target, including OpenResty 1.31.8.1 under the same full KeyUpdate pressure (`key_updates=262144`, `carrier=7340032`) and Node.js `http2`, HAProxy 3.0.31, and OpenLiteSpeed 1.9.4 Open under the soft profile (`key_updates=0`, `carrier=200000`). The OpenResty PASS was repeated. The Node, HAProxy, and OpenLiteSpeed PASSes are one run each. The vulnerable signature was not observed on those four. That is not a new CVE and not a claim that OpenResty 1.31.8.1 contains the nginx fix. A future FAIL on this nginx 1.31.8 line would be inheritance of CVE-2026-123007.
- OpenResty `wu_stream_overflow` and `settings_iw_overflow` FAIL the same way they FAIL on both nginx 1.31.8 and nginx 1.31.9. Those rows are not the CVE discriminator.
- Node `wu_zero_stream`, `wu_stream_overflow`, and `settings_iw_overflow` are ANOMALY: the connection closed with no GOAWAY. Review items, not CVE claims. `wu_zero_conn` and `wu_conn_overflow` returned GOAWAY and PASS.
- HAProxy `wu_zero_stream` and `wu_stream_overflow` are ANOMALY: RST_STREAM on the stream, connection kept. Same review bucket as Caddy. `wu_zero_conn` and `wu_conn_overflow` returned GOAWAY and PASS. `settings_iw_overflow` scored FAIL because the connection stayed up, answered PING, and sent no RST or GOAWAY. The probe request already carries END_STREAM, and `http-request return file` answers at once with the whole body. That score is a review item. It is not a new CVE. A tiny HTTP sidecar behind HAProxy is the follow-up if that row should be re-checked against a real stream.
- OpenLiteSpeed `wu_zero_stream` and `wu_stream_overflow` are ANOMALY: RST_STREAM on the stream, connection kept. Same review bucket as Caddy and HAProxy. `wu_zero_conn` and `wu_conn_overflow` returned GOAWAY and PASS. `settings_iw_overflow` scored FAIL because the connection stayed up, answered PING, and sent no RST or GOAWAY. The probe request already carries END_STREAM, and WINDOW_UPDATE(MAX-1) gives enough credit to finish the 896-byte body in that flight. That score is a review item. It is not a new CVE.
- nginx / Apache cleanup runs under full KeyUpdate pressure. Caddy / Envoy / Go / nghttpd / Node / HAProxy / OpenLiteSpeed complete under a soft profile (`key_updates=0`, `carrier=200000`); full KeyUpdate pressure hits Broken pipe on the earlier non-nginx stacks. Node, HAProxy, and OpenLiteSpeed were not driven at that pressure. Soft-profile PASS means the accounting signal was not observed under that load — see Scope. HAProxy's PASS also sits on a frontend that ignores Range. OpenLiteSpeed's static handler does implement Range; the cleanup canary on that run still observed 0 bytes.
- Other FAIL/ANOMALY rows are RFC-conformance / review items (`evidence/MANUAL-REVIEW-NOTES.txt`). nginx `wu_stream_overflow` / `settings_iw_overflow` FAIL on both vuln and patched builds, so they are not the CVE discriminator; likely probe over-strictness pending an h2spec overflow cross-check.

---

## ANOMALY / FAIL triage

Every ANOMALY cell, every `settings_iw_overflow` FAIL, and the nginx-family overflow FAILs (26 cells in all) were reviewed by hand against per-target transcripts, framing captures and h2spec where available. The classifier is mechanical, so the hand review is the part that decides whether a cell deserves attention. Full table and mechanics: `evidence/ANOMALY-TRIAGE.md`. These verdicts are my judgment, not proof.

| Verdict | Cells | What it covers |
|---------|-------|----------------|
| **IGNORE** | 13 | The server rejects the illegal frame with a stream-scoped `RST_STREAM` and keeps the connection (Caddy, Go, HAProxy, OpenLiteSpeed, httpd, nghttpd, Envoy `settings_iw_overflow`). RFC 9113 §6.9 prefers a connection error (`GOAWAY`), but h2spec still passes and nothing is accepted. A strictness gap. |
| **WATCH** | 9 | Hard close with no `GOAWAY` (Envoy, Node), where the rejection is real but opaque; plus HAProxy and OpenLiteSpeed `settings_iw_overflow` FAILs that look like probe early-completion (the request carries `END_STREAM` and the 896-byte body fits in the granted credit, so the stream finishes before an overflow is forced). Kept on the matrix with optional follow-ups. |
| **DIG** | 4 | `wu_stream_overflow` and `settings_iw_overflow` FAIL on nginx 1.31.8, nginx 1.31.9 and OpenResty. They also fire on the patched build, so they are not the CVE-2026-123007 discriminator. Worth one conformance write-up (h2spec §6.9.1 / §6.9.2 and a framing capture of the MAX→MAX+1 flight) documenting whether nginx clamps, ignores or accepts the overflow. Not a CVE claim. |

Only a `cleanup_overcredit` FAIL on a stack that is not the already-known nginx line would justify escalation. None occurred.

---

## Methodology note: verify before claim

An early widen-slice run showed Apache, Envoy, and nghttpd failing `wu_zero_stream` (apparently accepting a zero-length stream `WINDOW_UPDATE`). That looked like a shared RFC §6.9.1 deviation. Re-examination showed the probe was wrong: it sent WU(0) after `END_STREAM` on a closed / half-closed stream. Several stacks ignore illegal WUs in that state.

The corrected probe opens the stream with HEADERS `END_HEADERS` only (no `END_STREAM`) and sends WU(0) immediately — aligned with h2spec `http2/6.9/2`. Frame sent:

```
00 00 04 08 00 00 00 00 01 00 00 00 00
|len=4|type=WINDOW_UPDATE|flags=0|stream=1|increment=0|
```

Result: nginx, Apache, and nghttpd reject with GOAWAY `PROTOCOL_ERROR` (PASS). Caddy and Go reject via RST_STREAM; Envoy hard-closes — rejection-style differences, scored ANOMALY. **h2spec v2.6.0** (`http2/6.9/1` + `http2/6.9/2`) passed 2/2 on all seven h2 targets then in the lab. The earlier shared-FAIL claim was dropped. Evidence: `evidence/zero-wu/`.

---

## Scope & limitations

Deliberate design:

- **Lab-only, loopback-only** (`127.0.0.1`). Drivers refuse non-loopback hosts.
- **Accounting proof, not RCE.** No ~119 GiB / 2^64 walk; no exploit amplifier in `ours/`.
- **Coordinated-disclosure intent.** Method + lab, not an Internet scanner.
- **No new CVE** is claimed from this battery.

Current engineering limits (read before quoting a PASS):

- **KeyUpdate pressure is split.** nginx 1.31.8, nginx 1.31.9, OpenResty and Apache httpd run `cleanup_overcredit` at full pressure (`key_updates=262144`, `carrier=7340032`). Caddy, Envoy, Go, nghttpd, Node, HAProxy and OpenLiteSpeed run the soft profile (`key_updates=0`, `carrier=200000`): full pressure hits Broken pipe on the earlier non-nginx stacks, and Node, HAProxy and OpenLiteSpeed were not driven at it. Soft-profile PASSes are weaker evidence.
- **PASS is not immunity.** PASS means the accounting signal was not observed under that profile and probe. Each non-nginx PASS is a single run; only OpenResty's cleanup PASS was repeated before this full run.
- **HAProxy has no Range.** `http-request return file` ignores Range, so the fill/canary path is degraded. The probe completed, but it is not a like-for-like test of the nginx window math, and HAProxy in front of a real backend is a different system. A sidecar backend would be a separate slice.
- **OpenLiteSpeed here is OLS 1.9.4 Open, not LSWS Enterprise.** Enterprise is a different product and is not covered.
- **Cloudflare, Fastly and Akamai are out of scope.** Closed edge networks cannot be tested on loopback, and this lab does no internet scanning.
- **OpenResty is not independent of nginx.** It tracks the nginx 1.31.8 line. A cleanup FAIL there would be inheritance of CVE-2026-123007; a PASS is not a claim that the build contains the fix.
- **Static 896-byte body.** `settings_iw_overflow` on static or `return` frontends can score FAIL through early completion rather than an accepted overflow (HAProxy, OpenLiteSpeed).
- Envoy `direct_response` ignores HTTP Range; window-exhaustion via Range is degraded there.
- nginx overflow FAILs on both builds still need the h2spec overflow cross-check.
- `nghttpd` apt package version floats on a pinned debian base (reference baseline).

---

## Reproducibility

```bash
./scripts/run-all.sh                 # up + test + battery
./scripts/run-all.sh --skip-heavy    # skip ~45s cleanup_overcredit
```

Pipeline: dockerd → pinned targets up → 28 offline unit tests → 7-probe battery → matrix. Exit 0 means the harness succeeded (FAIL/ANOMALY in the matrix are observations). Tear down: `./scripts/lab-down-targets.sh`.

```bash
./scripts/capture-zero-wu.py
./scripts/run-h2spec-zero-wu.sh
```

Official images are digest-pinned; `go-nethttp` rebuilds from pinned golang with stdlib only. `node-http2` rebuilds from pinned `node:22-alpine` (v22.23.5) with stdlib `http2` only. The Node app is not separately hashed. `haproxy-3.0` is the pinned `haproxy:3.0-alpine` digest (3.0.31 LTS). The lab config is not separately hashed. `openlitespeed-1.9.4` is the pinned `litespeedtech/openlitespeed:1.9.4-lsphp82` digest. OLS is open source, not LSWS Enterprise. The lab entrypoint is not separately hashed.

---

## Results at a glance

**Established**

- nginx 1.31.8 breaks the connection-window accounting invariant.
- nginx 1.31.9 and Apache hold it under full KeyUpdate pressure.
- Caddy / Envoy / Go / nghttpd: signal not observed under the soft profile; probes completed.
- Method runs across twelve loopback targets.
- OpenResty 1.31.8.1 completed full-pressure `cleanup_overcredit` without the accounting signal (two runs). Not a new CVE and not a vendor-fix claim.
- Node.js stdlib `http2` (v22.23.5) completed soft-profile `cleanup_overcredit` without the accounting signal (one run). Not a new CVE.
- HAProxy 3.0.31 completed soft-profile `cleanup_overcredit` without the accounting signal (one run). Range is ignored by return-file. The `settings_iw_overflow` FAIL on that frontend is a review item, not a new CVE.
- OpenLiteSpeed 1.9.4 Open completed soft-profile `cleanup_overcredit` without the accounting signal (one run). Static Range works. The `wu_zero_stream` / `wu_stream_overflow` ANOMALYs and the `settings_iw_overflow` FAIL are review items, not a new CVE. This target is open-source OLS, not LSWS Enterprise.
- Zero-WU false positive identified, corrected, and h2spec-verified.

**Out of scope for this write-up**

- New CVEs on non-nginx targets, including OpenResty, Node, HAProxy, and OpenLiteSpeed.
- Reading the OpenResty 1.31.8.1 PASS as proof the nginx fix is present in that build.
- Equating soft-profile PASS with nginx-pressure immunity.
- Memory corruption or RCE proofs.

---

## Future work

1. Range-capable (or canary-fill) path for Envoy cleanup.
2. Full KeyUpdate pressure on non-nginx stacks without Broken pipe, or keep soft-profile semantics explicit.
3. h2spec cross-check of nginx `wu_stream_overflow` / `settings_iw_overflow`.
4. The expand-targets set is wired: OpenResty (`127.0.0.1:19452`), Node stdlib `http2` (`127.0.0.1:19454`), HAProxy 3.0.31 (`127.0.0.1:19453`), and OpenLiteSpeed 1.9.4 Open (`127.0.0.1:19451`). OLS in this lab is open source, not LSWS Enterprise. Optional follow-up: HAProxy plus a tiny HTTP sidecar, still loopback-published only through HAProxy, so Range and a real stream lifecycle can be re-checked. Traefik stays rejected for now.
5. After the HTTP/2 battery is settled: map the same invariant ideas onto other protocols as a separate standalone slice.

---

## How to add a target

1. Listener on **127.0.0.1:PORT** with TLS + ALPN `h2`, ~500–8192 byte Range-capable body.
2. Register in `ours/targets.py`:

```python
TARGETS["my-server"] = Target(
    id="my-server",
    name="My HTTP/2 server (lab)",
    url="https://127.0.0.1:19455/",
    role="cross-impl",
    image="owner/image@sha256:…",
    supports_h2=True,
)
```

3. Extend `lab-up-targets.sh` / `docker-compose.yml` / `lab-down-targets.sh`.
4. `./scripts/run-battery.sh --targets my-server` (or `./scripts/run-all.sh`).

New protocol later = new driver + probes; keep `oracle` / `Status` shared.

---

## Sources

- Rapid7: https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/
- RFC 9113: https://www.rfc-editor.org/rfc/rfc9113.html
- arkrwn PoC: https://github.com/arkrwn/NGINX2Root-CVE-2026-123007
- Rapid7 reproduction: https://github.com/sfewer-r7/CVE-2026-123007
