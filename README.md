# HTTP/2 Flow-Control Integer-Bug Lab

Reproducible **loopback** lab + invariant battery for the HTTP/2 flow-control /
counter / length integer-bug class (CWE-191), validated against nginx
CVE-2026-123007.

**Validated result:** the `cleanup_overcredit` probe **FAIL**s on nginx 1.31.8
(known-vulnerable) and **PASS**es on nginx 1.31.9 (patched), on Apache,
Caddy, Envoy, Go `net/http`, nghttpd, on OpenResty 1.31.8.1, on Node.js
stdlib `http2`, and on HAProxy 3.0.31. The nginx pair matches arkrwn's public
`--safe` PoC on the same listeners. Eleven loopback targets; seven RFC 9113
probes; one-command run.

Longer write-up: **[WRITEUP.md](WRITEUP.md)**.

- Loopback only (`127.0.0.1`). Drivers refuse non-loopback hosts.
- Lab-only, coordinated-disclosure. No internet scanning. No RCE. No ~119 GiB /
  2^64 walk. Not tied to Jig or any other project.

## Quick start

```bash
git clone https://github.com/c0re-i5/intbug-lab.git
cd intbug-lab
python3 -m venv .venv && .venv/bin/pip install -r ours/requirements.txt
./scripts/run-all.sh          # or: make battery
```

That brings up the pinned targets, runs offline unit tests, and writes the
matrix under `evidence/`. Tear down with `./scripts/lab-down-targets.sh`
(or `make down`).

### Optional: third-party ground truth (not required for the battery)

```bash
# arkrwn --safe PoC (for scripts/proof.sh cross-check)
git clone https://github.com/arkrwn/NGINX2Root-CVE-2026-123007.git \
  detectors/arkrwn-nginx2root
(cd detectors/arkrwn-nginx2root && cargo build --release)

# Rapid7 reproduction notes (reference only)
git clone https://github.com/sfewer-r7/CVE-2026-123007.git \
  detectors/sfewer-r7-cve

# h2spec for the optional zero-WU RFC cross-check (make zero-wu)
# see bin/README.md for the download command
```

Details: [`detectors/README.md`](detectors/README.md), [`bin/README.md`](bin/README.md).

## One-command entrypoint

```bash
make battery          # = ./scripts/run-all.sh
# or, skip the ~45s heavy probe:
make battery-light    # = ./scripts/run-all.sh --skip-heavy
```

`./scripts/run-all.sh` is the canonical one-command (also exposed as `make battery` when GNU make is installed). It is idempotent:

1. ensure dockerd (`./scripts/box-dockerd.sh`)
2. bring all pinned targets up (`./scripts/lab-up-targets.sh`)
3. run offline unit tests
4. run the 7-probe battery across every registered target and write the matrix

Exit codes: `0` after a successful harness run (FAIL/ANOMALY in the matrix are
*observations*, not harness failures). Non-zero only if docker is unreachable,
unit tests fail, or the battery crashes.

Tear down: `make down` (or `./scripts/lab-down-targets.sh`).

## Targets (pinned)

| id | Role | Listen | Image digest |
|----|------|--------|--------------|
| `nginx-1.31.8` | known-vulnerable (CVE-2026-123007) | `127.0.0.1:19443` | `nginx@sha256:5ab5b0b01097420873a3f3330f44248e34a3c2a3e8d5ee30658aeae8cb7435da` |
| `nginx-http2-off` | negative control (same image, `http2` off) | `127.0.0.1:19444` | same as above |
| `httpd-2.4.71` | cross-impl (Apache + mod_http2) | `127.0.0.1:19445` | `httpd@sha256:32e9403360ab2f1047523e72f256527fb9aee68b342abf6ad03f0d629157f3d9` |
| `nginx-1.31.9` | patched clean control | `127.0.0.1:19446` | `nginx@sha256:08f354a3b44c422021a5c0f5efb3e27f8f90236b5447d3bac4053f5f50ab6760` |
| `caddy-2.10` | cross-impl (Caddy) | `127.0.0.1:19447` | `caddy@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb` |
| `envoy-1.32` | cross-impl (Envoy) | `127.0.0.1:19448` | `envoyproxy/envoy@sha256:6bf0d37dd5e8eac4b37effe89a1aec4760f7f2ce860d1fd6af22147eb87a5058` |
| `go-nethttp` | cross-impl (Go `net/http` stdlib) | `127.0.0.1:19449` | built from `golang@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac` |
| `nghttpd` | reference (nghttp2) | `127.0.0.1:19450` | built from `debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc` (+ apt `nghttp2-server`, not itself digest-pinned) |
| `openresty-1.31.8.1` | nginx-family (OpenResty on the nginx 1.31.8 line) | `127.0.0.1:19452` | `openresty/openresty@sha256:2cb90d64192934c26b3749cf744f47edd59277787fe761bd109eeebdc3e2214a` |
| `haproxy-3.0` | cross-impl (HAProxy 3.0.31 LTS, `http-request return`) | `127.0.0.1:19453` | `haproxy@sha256:7430e63d3052198b18a40665b59a5826bc428e8bceb0c561d82258149ef855ee` (`:3.0-alpine` → 3.0.31) |
| `node-http2` | cross-impl (Node.js stdlib `http2`) | `127.0.0.1:19454` | built from `node@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a` (`:22-alpine` → v22.23.5) |

All publishes are **127.0.0.1 only**. Bodies are the 896-byte `/index.html`.

OpenResty **1.31.8.1** (`:alpine` digest above) is still the nginx **1.31.8** line. It is registered as `nginx-family` and driven with the same full KeyUpdate pressure as `nginx-1.31.8` (no soft-profile fallback). A `cleanup_overcredit` **FAIL** on this target is inheritance of the known nginx bug class ([CVE-2026-123007](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/)), not a new CVE. Re-pin when OpenResty publishes a 1.31.9+ or backported image. Do not use the `:latest` tag.

The alpine image does not ship an `openssl` CLI. The entrypoint runs `apk add --no-cache openssl` and then the same self-signed cert command as the nginx targets. That package is only the lab certificate; the server under test remains the pinned OpenResty digest.

Node.js stdlib `http2` (`conf/node/`) is built the same way as `go-nethttp`: digest-pinned `node:22-alpine` (v22.23.5), no npm install, lab certs mounted from `certs/lab.{crt,key}`. The image tag after build is `integer-lab-node:pinned`. The base digest is pinned; `server.js` is not separately hashed. The container listens on 443 and is published only as `127.0.0.1:19454`. This target uses the soft cleanup profile (`key_updates=0`, `carrier=200000`), same as Go and Caddy. `allowHTTP1` is on; the smoke check is HTTP/2.

HAProxy **3.0.31** LTS (`:3.0-alpine` digest above) is one container. The frontend binds `:443` with `alpn h2,http/1.1` and answers `/` and `/index.html` with `http-request return … file` (the shared 896-byte index). There is no second backend. The entrypoint concatenates `certs/lab.crt` and `certs/lab.key` into the PEM HAProxy loads. The image USER is `haproxy`, so the lab runs the entrypoint as root only to write that PEM. The publish is still `127.0.0.1:19453`. HAProxy 3.0.31 does not treat a trailing backslash as a line continuation, so the return rule is one line. `http-request return file` does not implement Range: `Range: bytes=0-9` smoked as HTTP/2 200, 896 bytes. The registered cleanup profile is the soft one (`key_updates=0`, `carrier=200000`). Traefik was not selected.

### Reproducibility limits (honest)

- Official images (nginx / httpd / caddy / envoy / golang / debian / openresty / haproxy / node) are **digest-pinned**. The OpenResty, HAProxy, and Node base digests must match `ours/targets.py`, `docker-compose.yml`, and `scripts/lab-up-targets.sh`.
- `go-nethttp` is rebuilt from the pinned golang digest with **stdlib only** (no module fetch).
- `haproxy-3.0` is the official `haproxy:3.0-alpine` digest (3.0.31 LTS). The lab config and entrypoint are not separately hashed.
- `node-http2` is rebuilt from the pinned `node:22-alpine` digest (v22.23.5) with **stdlib `http2` only** (no npm install). The lab app is not separately hashed.
- `nghttpd` installs `nghttp2-server` via apt on a pinned debian base — the apt package
  version floats with the distro snapshot. Treat it as a *reference baseline*, not a
  bit-for-bit pin. Documented here so nobody pretends otherwise.

## Invariant battery (bug class, not one CVE)

Implemented in `ours/battery.py`. Each probe cites RFC 9113 (HTTP/2).

| Probe id | What it checks | RFC |
|----------|----------------|-----|
| `h2_alpn` | ALPN `h2` present/absent as expected | §3.3 / RFC 7301 |
| `wu_zero_conn` | `WINDOW_UPDATE` increment 0 on connection → `PROTOCOL_ERROR` | §6.9.1 |
| `wu_zero_stream` | `WINDOW_UPDATE` increment 0 on stream → `PROTOCOL_ERROR` | §6.9.1 |
| `wu_conn_overflow` | connection WU that would exceed `MAX=2^31-1` → `FLOW_CONTROL_ERROR` | §6.9.1 |
| `wu_stream_overflow` | stream WU that would exceed MAX → `FLOW_CONTROL_ERROR` | §6.9.1 |
| `settings_iw_overflow` | `SETTINGS_INITIAL_WINDOW_SIZE` delta pushing a stream past MAX | §6.9.2 |
| `cleanup_overcredit` | queued-DATA cleanup must not drive connection window above MAX; post-refund WU guard (CVE-2026-123007 *accounting* class) | §6.9 / CWE-191 |

Statuses: **PASS** (invariant held), **FAIL** (invariant broken — bug-class signal),
**ANOMALY** (needs manual review, **not** a confirmed CVE),
**INCONCLUSIVE** (probe could not complete — **not** a PASS), **SKIP**, **ERROR**.

Heavy probe `cleanup_overcredit` ≈ 14 MiB / ~45s per target. Skip with
`./scripts/run-battery.sh --skip-heavy` or `make battery-light`.

## Results matrix (this box, 2026-11-19 America/Toronto)

From `evidence/BATTERY-MATRIX-latest.txt`. The HAProxy column is this slice
(one full battery). The other columns are the prior Node matrix and were
not re-run.

```
probe                | nginx-1.31.8 | nginx-http2-off | httpd-2.4.71 | nginx-1.31.9 | caddy-2.10 | envoy-1.32 | go-nethttp | nghttpd | openresty-1.31.8.1 | node-http2 | haproxy-3.0
h2_alpn              | PASS         | PASS            | PASS         | PASS         | PASS       | PASS       | PASS       | PASS    | PASS                | PASS       | PASS
wu_zero_conn         | PASS         | -               | PASS         | PASS         | PASS       | ANOMALY    | PASS       | PASS    | PASS                | PASS       | PASS
wu_zero_stream       | PASS         | -               | PASS         | PASS         | ANOMALY    | ANOMALY    | ANOMALY    | PASS    | PASS                | ANOMALY    | ANOMALY
wu_conn_overflow     | PASS         | -               | PASS         | PASS         | PASS       | ANOMALY    | PASS       | PASS    | PASS                | PASS       | PASS
wu_stream_overflow   | FAIL         | -               | ANOMALY      | FAIL         | ANOMALY    | ANOMALY    | ANOMALY    | ANOMALY | FAIL                | ANOMALY    | ANOMALY
settings_iw_overflow | FAIL         | -               | ANOMALY      | FAIL         | PASS       | ANOMALY    | PASS       | ANOMALY | FAIL                | ANOMALY    | FAIL
cleanup_overcredit   | FAIL         | -               | PASS         | PASS         | PASS       | PASS       | PASS       | PASS    | PASS                | PASS       | PASS
```

`cleanup_overcredit` **completes** on all 10 h2 targets (no Broken-pipe soft-PASS).
caddy/envoy/go/nghttpd/node/haproxy use `key_updates=0` / `carrier=200000` (full KeyUpdate
pressure hits Broken pipe on the earlier non-nginx stacks; Node and HAProxy were not driven
at that pressure). OpenResty uses the nginx full-pressure profile
(`key_updates=262144`, `carrier=7340032`). On the OpenResty pin the accounting
signal was not observed (PASS, twice). Node's soft-profile run also PASSed
once: no RST `FLOW_CONTROL_ERROR`, canary 0/10, no post-refund PING ACK.
HAProxy's soft-profile run PASSed once as well. Streams 149/151 got RST error
code 0, canary 0/10, no post-refund PING ACK. The probe completed. It is not
INCONCLUSIVE. `http-request return file` ignores Range, so the fill/canary
path is degraded. That is a completed NOT_PROVEN under the soft profile. It
is not a new CVE, and it is not a claim that HAProxy is immune under nginx
KeyUpdate pressure or in front of a real backend.
OpenResty's PASS is the same NOT_PROVEN shape as nginx 1.31.9's transcript
and is not a claim that OpenResty 1.31.8.1 has shipped the nginx fix.
`wu_stream_overflow` and `settings_iw_overflow` FAIL on OpenResty the same
way they FAIL on both nginx 1.31.8 and 1.31.9, so they are not the CVE
discriminator. Node's `wu_zero_stream`, `wu_stream_overflow`, and
`settings_iw_overflow` are ANOMALY (connection closed, no GOAWAY).
HAProxy's `wu_zero_stream` and `wu_stream_overflow` are ANOMALY (stream RST,
connection kept). HAProxy's `settings_iw_overflow` scored FAIL: the connection
stayed up, answered PING, and sent no RST or GOAWAY. The request in that flight
already has END_STREAM, and the return-file frontend answers immediately with
the whole file. That score is a review item. It is not a new CVE. See
`evidence/MANUAL-REVIEW-NOTES.txt`.

`wu_zero_stream` prior FAILs on Apache/Envoy/nghttpd were a **probe artifact**
(WU after END_STREAM). Open-stream (h2spec-aligned) probe + byte capture +
h2spec http2/6.9/1+2 cross-check transcripts are under `evidence/zero-wu/` (optional binary; see `bin/README.md`).

## How to read the matrix (honesty rules)

- **`cleanup_overcredit` is the only genuine CVE-class discriminator so far.**
  It FAILs on nginx 1.31.8 and PASSes on patched nginx 1.31.9 and on Apache
  under the full KeyUpdate pressure profile. Matches public arkrwn `--safe`.
  OpenResty 1.31.8.1 also PASSed under that same full-pressure profile. The
  vulnerable signature was not observed. That PASS is not a new CVE and not
  a claim that this OpenResty build contains the nginx fix. A future FAIL on
  the nginx 1.31.8 line, including OpenResty, is inheritance of
  CVE-2026-123007. Node stdlib `http2` and HAProxy 3.0.31 also PASSed, under
  the soft profile only. That is not a new CVE.
  Other FAIL/ANOMALY rows, including HAProxy `settings_iw_overflow`, stay
  review items.
- A soft-profile PASS on caddy/envoy/go/nghttpd/node/haproxy means the
  accounting signal was not observed under `key_updates=0`. It does not
  establish immunity under nginx KeyUpdate pressure. Incomplete runs are
  `INCONCLUSIVE`. A completed run is never rewritten into a PASS.
- Other FAIL/ANOMALY rows are **RFC-conformance / review items**. They go in
  `evidence/MANUAL-REVIEW-NOTES.txt` as "needs manual review", never as findings.
- We never invent CVE IDs from this lab alone.

Latest matrix: `evidence/BATTERY-MATRIX-latest.txt`. Dated copies are kept alongside.

## How to add a target (few lines)

1. Bring up a container (or native) listener on **127.0.0.1:PORT** with TLS + ALPN `h2`,
   serving an ~500–8192 byte Range-capable body.
2. Register it in `ours/targets.py`:

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

3. Extend `scripts/lab-up-targets.sh` / `docker-compose.yml` / `lab-down-targets.sh`.
4. Run: `./scripts/run-battery.sh --targets my-server` (or `make battery`).

Adding a **new protocol** later = new driver module + probes; keep `oracle`/`Status` shared.

## Layout

```
intbug-lab/
  Makefile                 # make battery | up | down | test
  README.md
  docker-compose.yml
  conf/
    nginx.conf / nginx-http2-off.conf
    apache/  caddy/  envoy/  go/  nghttpd/  openresty/  haproxy/  node/  shared/
  ours/
    framing.py             # raw HTTP/2 encoder (adversarial WUs allowed)
    driver.py              # cleanup-overcredit counter-driver
    oracle.py              # status vocabulary + legacy CVE evaluator
    battery.py             # multi-invariant probe suite
    targets.py             # extensible target registry
    run_battery.py         # CLI matrix runner
    run_proof.py           # slice-2 single-target proof
    tests/                 # offline unit tests (no network)
  scripts/
    run-all.sh             # one-command: up + test + battery
    lab-up-targets.sh / lab-down-targets.sh
    run-battery.sh / box-dockerd.sh / ours-proof.sh / proof.sh
    capture-zero-wu.py / run-h2spec-zero-wu.sh
  bin/README.md            # optional: download h2spec / build poc-safe
  detectors/README.md      # optional: clone arkrwn + Rapid7 PoCs (not vendored)
  evidence/                # transcripts + matrices + MANUAL-REVIEW-NOTES.txt
  evidence/zero-wu/        # framing captures + h2spec cross-check
  WRITEUP.md               # research write-up
  LICENSE                  # MIT
```

## Safety

- Drivers refuse non-loopback hosts (`ours/battery.py::_assert_loopback`,
  `ours/driver.py` URL parse).
- No `--exploit` / crash amplifier / 2^64 walk in this repo’s “ours” tooling.
- ANOMALY ≠ vulnerability. Read `evidence/MANUAL-REVIEW-NOTES.txt` before escalating.
- Do not publish external scans or claim CVEs from FAIL/ANOMALY alone.

## What is (and is not) proven

**Proven in this lab (against public arkrwn `--safe`):**

- nginx 1.31.8 breaks the connection-window accounting invariant (`cleanup_overcredit` FAIL).
- nginx 1.31.9 and Apache httpd 2.4.71 hold it under full KeyUpdate pressure.
- caddy / envoy / go / nghttpd: accounting signal **not observed** under the soft
  profile (`key_updates=0`, `carrier=200000`); probe **completed** (not a soft-PASS).
- The battery runs across 11 loopback targets so the *method* is not nginx-specific.
- OpenResty 1.31.8.1 (`openresty/1.31.8.1`, nginx 1.31.8 line) completed
  `cleanup_overcredit` under full KeyUpdate pressure without the accounting
  signal (two runs). Not a new CVE and not a vendor-fix claim.
- Node.js stdlib `http2` (v22.23.5) completed `cleanup_overcredit` under the
  soft profile without the accounting signal (one run). Not a new CVE.
- HAProxy 3.0.31 completed `cleanup_overcredit` under the soft profile without
  the accounting signal (one run). Range is ignored by `http-request return
  file`. Not a new CVE. The `settings_iw_overflow` FAIL on that return-file
  frontend is a review item, not a finding.
- `wu_zero_stream` open-stream probe matches h2spec §6.9 on the stacks that PASS;
  prior Apache/nghttpd FAILs were our probe bug (documented + withdrawn).

**Not proven / not claimed:**

- Any new CVE on Apache, Caddy, Envoy, Go, nghttpd, OpenResty, Node, or HAProxy.
- That an OpenResty 1.31.8.1 PASS means the nginx 1.31.8 fix is present in that build.
- That soft-profile PASS equals "immune under nginx-style KeyUpdate pressure".
- Memory corruption or RCE (we never walk to 2^64).
- That every FAIL/ANOMALY is a security bug — many are RFC-strictness gaps.

## Zero-WU cross-check helpers

```bash
./scripts/capture-zero-wu.py          # framing-level hex transcripts → evidence/zero-wu/
./scripts/run-h2spec-zero-wu.sh       # h2spec http2/6.9/1 + 6.9/2 on all loopback targets
```

Place summerwind h2spec v2.6.0 at `bin/h2spec` (see `bin/README.md`). Framing-level
capture (`./scripts/capture-zero-wu.py`) is the authoritative byte evidence for our
WU frames (TLS would hide them in a pcap anyway).

## Suggested next slice

1. Optional: Range-capable Envoy upstream (or no-Range fill/canary path) so the
   soft-profile cleanup on Envoy matches nginx window math more closely.
2. h2spec cross-check of nginx `wu_stream_overflow` / `settings_iw_overflow` FAILs
   (present on both vuln and patched — still not the CVE discriminator).
3. OpenLiteSpeed on `127.0.0.1:19451`. HAProxy 3.0.31 is wired on
   `127.0.0.1:19453` and Node stdlib `http2` on `127.0.0.1:19454`.
   Optional follow-up: HAProxy in front of a tiny HTTP sidecar, still
   published only on loopback, so Range and a real stream lifecycle can be
   re-checked. Traefik stays a rejected-for-now note from the expand draft.
4. Only after the HTTP/2 battery is dull: map the *same invariant ideas*
   onto other protocols as a **separate** slice — still standalone.

## Sources

- Rapid7: https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/
- RFC 9113: https://www.rfc-editor.org/rfc/rfc9113.html
- arkrwn PoC: https://github.com/arkrwn/NGINX2Root-CVE-2026-123007
- Rapid7 reproduction: https://github.com/sfewer-r7/CVE-2026-123007
