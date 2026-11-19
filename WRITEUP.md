# HTTP/2 Flow-Control Integer-Bug Lab

**A reproducible lab that detects the HTTP/2 flow-control integer-bug class (CWE-191) and validates it against nginx CVE-2026-123007 across eight real servers.**

*Research write-up — 2026-11-19 (America/Toronto)*

---

## Summary

This project is a standalone, one-command lab for the **class** of HTTP/2 flow-control / counter / length integer bugs. It runs a seven-probe invariant battery against eight loopback HTTP/2 implementations and **reliably distinguishes** the known nginx CVE-2026-123007 accounting bug from patched nginx and from every other stack under test.

On nginx 1.31.8 (known-vulnerable), the `cleanup_overcredit` probe fails. On nginx 1.31.9 (patched) and on Apache, Caddy, Envoy, Go `net/http`, and nghttpd, the same probe passes. That result matches arkrwn's public `--safe` PoC on the same listeners. The method is target-agnostic; adding a server is a few lines in `ours/targets.py`.

No new vulnerability is reported from this work. The deliverable is a **working, validated method** — not a one-CVE detector that expires when nginx is patched.

| | |
|---|---|
| Targets | 8 loopback HTTP/2 servers |
| Probes | 7 RFC 9113 invariants |
| Offline tests | 24 |
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

Bodies: 896-byte `/index.html` (Range-capable where supported).

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

From `evidence/BATTERY-MATRIX-latest.txt` (2026-11-19 America/Toronto):

| probe | nginx-1.31.8 | http2-off | httpd-2.4.71 | nginx-1.31.9 | caddy | envoy | go | nghttpd |
|-------|--------------|-----------|--------------|--------------|-------|-------|-----|---------|
| `h2_alpn` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| `wu_zero_conn` | PASS | — | PASS | PASS | PASS | ANOMALY | PASS | PASS |
| `wu_zero_stream` | PASS | — | PASS | PASS | ANOMALY | ANOMALY | ANOMALY | PASS |
| `wu_conn_overflow` | PASS | — | PASS | PASS | PASS | ANOMALY | PASS | PASS |
| `wu_stream_overflow` | FAIL | — | ANOMALY | FAIL | ANOMALY | ANOMALY | ANOMALY | ANOMALY |
| `settings_iw_overflow` | FAIL | — | ANOMALY | FAIL | PASS | ANOMALY | PASS | ANOMALY |
| `cleanup_overcredit` | **FAIL** | — | PASS | PASS | PASS | PASS | PASS | PASS |

**Reading the matrix**

- `cleanup_overcredit` is the CVE-class discriminator: FAIL on nginx 1.31.8; PASS on patched nginx and every other h2 target.
- nginx / Apache cleanup runs under full KeyUpdate pressure. Caddy / Envoy / Go / nghttpd complete under a soft profile (`key_updates=0`, `carrier=200000`); full KeyUpdate pressure hits Broken pipe on those stacks. Soft-profile PASS means the accounting signal was not observed under that load — see Scope.
- Other FAIL/ANOMALY rows are RFC-conformance / review items (`evidence/MANUAL-REVIEW-NOTES.txt`). nginx `wu_stream_overflow` / `settings_iw_overflow` FAIL on both vuln and patched builds, so they are not the CVE discriminator; likely probe over-strictness pending an h2spec overflow cross-check.

---

## Methodology note: verify before claim

An early widen-slice run showed Apache, Envoy, and nghttpd failing `wu_zero_stream` (apparently accepting a zero-length stream `WINDOW_UPDATE`). That looked like a shared RFC §6.9.1 deviation. Re-examination showed the probe was wrong: it sent WU(0) after `END_STREAM` on a closed / half-closed stream. Several stacks ignore illegal WUs in that state.

The corrected probe opens the stream with HEADERS `END_HEADERS` only (no `END_STREAM`) and sends WU(0) immediately — aligned with h2spec `http2/6.9/2`. Frame sent:

```
00 00 04 08 00 00 00 00 01 00 00 00 00
|len=4|type=WINDOW_UPDATE|flags=0|stream=1|increment=0|
```

Result: nginx, Apache, and nghttpd reject with GOAWAY `PROTOCOL_ERROR` (PASS). Caddy and Go reject via RST_STREAM; Envoy hard-closes — rejection-style differences, scored ANOMALY. **h2spec v2.6.0** (`http2/6.9/1` + `http2/6.9/2`) passed 2/2 on all seven h2 targets. The earlier shared-FAIL claim was dropped. Evidence: `evidence/zero-wu/`.

---

## Scope & limitations

Deliberate design:

- **Lab-only, loopback-only** (`127.0.0.1`). Drivers refuse non-loopback hosts.
- **Accounting proof, not RCE.** No ~119 GiB / 2^64 walk; no exploit amplifier in `ours/`.
- **Coordinated-disclosure intent.** Method + lab, not an Internet scanner.
- **No new CVE** is claimed from this battery.

Current engineering limits:

- Soft-profile cleanup on caddy / envoy / go / nghttpd is not equivalent to nginx KeyUpdate pressure.
- Envoy `direct_response` ignores HTTP Range; window-exhaustion via Range is degraded there.
- nginx overflow FAILs on both builds need an h2spec overflow cross-check.
- `nghttpd` apt package version floats on a pinned debian base (reference baseline).

---

## Reproducibility

```bash
./scripts/run-all.sh                 # up + test + battery
./scripts/run-all.sh --skip-heavy    # skip ~45s cleanup_overcredit
```

Pipeline: dockerd → pinned targets up → 24 offline unit tests → 7-probe battery → matrix. Exit 0 means the harness succeeded (FAIL/ANOMALY in the matrix are observations). Tear down: `./scripts/lab-down-targets.sh`.

```bash
./scripts/capture-zero-wu.py
./scripts/run-h2spec-zero-wu.sh
```

Official images are digest-pinned; `go-nethttp` rebuilds from pinned golang with stdlib only.

---

## Results at a glance

**Established**

- nginx 1.31.8 breaks the connection-window accounting invariant.
- nginx 1.31.9 and Apache hold it under full KeyUpdate pressure.
- Caddy / Envoy / Go / nghttpd: signal not observed under the soft profile; probes completed.
- Method runs across eight real HTTP/2 stacks.
- Zero-WU false positive identified, corrected, and h2spec-verified.

**Out of scope for this write-up**

- New CVEs on non-nginx targets.
- Equating soft-profile PASS with nginx-pressure immunity.
- Memory corruption or RCE proofs.

---

## Future work

1. Range-capable (or canary-fill) path for Envoy cleanup.
2. Full KeyUpdate pressure on non-nginx stacks without Broken pipe, or keep soft-profile semantics explicit.
3. h2spec cross-check of nginx `wu_stream_overflow` / `settings_iw_overflow`.
4. Additional targets (Traefik, Hyper, …) via the same registry.
5. After the HTTP/2 battery is settled: map the same invariant ideas onto other protocols as a separate standalone slice.

---

## How to add a target

1. Listener on **127.0.0.1:PORT** with TLS + ALPN `h2`, ~500–8192 byte Range-capable body.
2. Register in `ours/targets.py`:

```python
TARGETS["my-server"] = Target(
    id="my-server",
    name="My HTTP/2 server (lab)",
    url="https://127.0.0.1:19451/",
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
