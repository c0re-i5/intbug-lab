# HTTP/2 Flow-Control Integer-Bug Lab

Reproducible **loopback** lab + invariant battery for the HTTP/2 flow-control /
counter / length integer-bug class (CWE-191), validated against nginx
CVE-2026-123007.

**Validated result:** the `cleanup_overcredit` probe **FAIL**s on nginx 1.31.8
(known-vulnerable) and **PASS**es on nginx 1.31.9 (patched) and on Apache,
Caddy, Envoy, Go `net/http`, and nghttpd — matching arkrwn's public `--safe`
PoC on the same listeners. Eight real HTTP/2 stacks; seven RFC 9113 probes;
one-command run.

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

All publishes are **127.0.0.1 only**. Bodies are 896-byte `/index.html` (Range-capable).

### Reproducibility limits (honest)

- Official images (nginx / httpd / caddy / envoy / golang / debian) are **digest-pinned**.
- `go-nethttp` is rebuilt from the pinned golang digest with **stdlib only** (no module fetch).
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

From `evidence/BATTERY-MATRIX-latest.txt` (graceful cleanup + open-stream wu_zero fix):

```
probe                | nginx-1.31.8    | nginx-http2-off | httpd-2.4.71    | nginx-1.31.9    | caddy-2.10      | envoy-1.32      | go-nethttp      | nghttpd
h2_alpn              | PASS            | PASS            | PASS            | PASS            | PASS            | PASS            | PASS            | PASS
wu_zero_conn         | PASS            | -               | PASS            | PASS            | PASS            | ANOMALY         | PASS            | PASS
wu_zero_stream       | PASS            | -               | PASS            | PASS            | ANOMALY         | ANOMALY         | ANOMALY         | PASS
wu_conn_overflow     | PASS            | -               | PASS            | PASS            | PASS            | ANOMALY         | PASS            | PASS
wu_stream_overflow   | FAIL            | -               | ANOMALY         | FAIL            | ANOMALY         | ANOMALY         | ANOMALY         | ANOMALY
settings_iw_overflow | FAIL            | -               | ANOMALY         | FAIL            | PASS            | ANOMALY         | PASS            | ANOMALY
cleanup_overcredit   | FAIL            | -               | PASS            | PASS            | PASS            | PASS            | PASS            | PASS
```

`cleanup_overcredit` now **completes** on all 8 h2 targets (no Broken-pipe soft-PASS).
caddy/envoy/go/nghttpd use `key_updates=0` / `carrier=200000` (full KeyUpdate pressure
hits Broken pipe on those stacks). See `evidence/MANUAL-REVIEW-NOTES.txt`.

`wu_zero_stream` prior FAILs on Apache/Envoy/nghttpd were a **probe artifact**
(WU after END_STREAM). Open-stream (h2spec-aligned) probe + byte capture +
h2spec http2/6.9/1+2 cross-check transcripts are under `evidence/zero-wu/` (optional binary; see `bin/README.md`).

## How to read the matrix (honesty rules)

- **`cleanup_overcredit` is the only genuine CVE-class discriminator so far.**
  It FAILs on nginx 1.31.8 and PASSes on patched nginx 1.31.9 and on Apache
  under the full KeyUpdate pressure profile. Matches public arkrwn `--safe`.
  Do **not** treat other FAIL/ANOMALY rows as CVEs.
- **PASS on cleanup ≠ "confirmed clean under nginx pressure"** for
  caddy/envoy/go/nghttpd — those complete under a soft profile (`key_updates=0`).
  Incomplete runs are `INCONCLUSIVE`, never a fabricated PASS.
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
    apache/  caddy/  envoy/  go/  nghttpd/  shared/
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
- The battery runs across 8 real HTTP/2 stacks so the *method* is not nginx-specific.
- `wu_zero_stream` open-stream probe matches h2spec §6.9 on the stacks that PASS;
  prior Apache/nghttpd FAILs were our probe bug (documented + withdrawn).

**Not proven / not claimed:**

- Any new CVE on Apache, Caddy, Envoy, Go, or nghttpd.
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
3. Optional: Hyper (Rust) / Traefik as more cross-impl targets.
4. Only after the HTTP/2 battery is dull: map the *same invariant ideas*
   onto other protocols as a **separate** slice — still standalone.

## Sources

- Rapid7: https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/
- RFC 9113: https://www.rfc-editor.org/rfc/rfc9113.html
- arkrwn PoC: https://github.com/arkrwn/NGINX2Root-CVE-2026-123007
- Rapid7 reproduction: https://github.com/sfewer-r7/CVE-2026-123007
