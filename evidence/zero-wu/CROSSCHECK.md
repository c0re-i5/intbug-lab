# Zero WINDOW_UPDATE cross-check (RFC 9113 §6.9.1)

Date: 2026-11-19 America/Toronto. Loopback-only. NOT a CVE claim.

## Frame we send

```
00 00 04 08 00 00 00 00 01 00 00 00 00
|len=4|type=WINDOW_UPDATE|flags=0|stream=1|increment=0|
```

Stream opened first with HEADERS flags=`END_HEADERS` only (no `END_STREAM`),
matching h2spec `http2/6.9/2`.

## Framing-level capture (`*-wu-zero-stream.txt`)

| target | classification |
|--------|----------------|
| nginx-1.31.8 | REJECTED_STRICT GOAWAY PROTOCOL_ERROR — PASS |
| nginx-1.31.9 | REJECTED_STRICT GOAWAY PROTOCOL_ERROR — PASS |
| httpd-2.4.71 | REJECTED_STRICT GOAWAY PROTOCOL_ERROR — PASS |
| nghttpd | REJECTED_STRICT GOAWAY PROTOCOL_ERROR — PASS |
| caddy-2.10 | RST_STREAM only — ANOMALY (h2spec still passes) |
| go-nethttp | RST_STREAM only — ANOMALY (h2spec still passes) |
| envoy-1.32 | hard close, no GOAWAY — ANOMALY (h2spec still passes) |

## h2spec v2.6.0 (`http2/6.9/1` + `http2/6.9/2`)

All seven h2 targets: **2 tests, 2 passed, 0 failed**. See `h2spec-*.txt`.

## Probe-artifact note

Earlier widen-slice FAILs on Apache/Envoy/nghttpd used WU after END_STREAM
(closed/half-closed stream). That is withdrawn. Byte evidence proves our
encoder emits a well-formed zero-increment WU; the remaining ANOMALYs are
rejection-*style* differences (RST / hard close vs GOAWAY), not "accepted".
