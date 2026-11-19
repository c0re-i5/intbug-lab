"""Extensible lab target registry (loopback HTTP/2 servers).

Add a target by appending to TARGETS below (or loading targets.yaml later).
Each entry names a URL, optional docker helper metadata, and which battery
probe groups to run by default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    url: str
    path: str = "/index.html"
    # Expected role in the lab matrix (documentation only).
    role: str = "subject"
    # Image pin for humans / lab-up scripts.
    image: str = ""
    # Default probe ids; empty = all probes that apply.
    probes: Sequence[str] = field(default_factory=tuple)
    # If False, skip heavy cleanup_overcredit (e.g. http2-off).
    supports_h2: bool = True
    # Notes shown in the matrix.
    notes: str = ""
    # --- cleanup_overcredit driver tuning ---
    # None = use DriverConfig library defaults (full KeyUpdate pressure).
    # Non-nginx stacks typically need key_updates=0 + a small carrier so the
    # cleanup flight completes; full KeyUpdate pressure hits Broken pipe.
    key_updates: int | None = None
    carrier_app_bytes: int | None = None
    # Soft-failure retry profile. None disables fallback.
    # Used when the primary profile raises Broken pipe / reset / empty body.
    fallback_key_updates: int | None = 0
    fallback_carrier_app_bytes: int | None = 200_000
    # If set, docker restart this container before the target's battery
    # (Envoy has been observed to exit after adversarial WU probes).
    restart_container: str = ""


# Ports: 19443 vuln nginx, 19444 http2-off, 19445 apache, 19446 patched nginx,
#         19447 caddy, 19448 envoy, 19449 go-nethttp, 19450 nghttpd,
#         19451 openlitespeed 1.9.4 (open source OLS, not LSWS Enterprise),
#         19452 openresty (nginx 1.31.8 line),
#         19453 haproxy 3.0 (return-file, no backend),
#         19454 node-http2.
TARGETS: dict[str, Target] = {
    "nginx-1.31.8": Target(
        id="nginx-1.31.8",
        name="nginx 1.31.8 (CVE-2026-123007 known-vulnerable)",
        url="https://127.0.0.1:19443/",
        role="known-vulnerable",
        image="nginx@sha256:5ab5b0b01097420873a3f3330f44248e34a3c2a3e8d5ee30658aeae8cb7435da",
        supports_h2=True,
        notes="Pinned Rapid7 reproduction image; needs full KeyUpdate pressure",
        # No fallback: ku=0 loses the CVE discriminator on this stack.
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
    "nginx-http2-off": Target(
        id="nginx-http2-off",
        name="nginx 1.31.8 TLS-only (http2 off)",
        url="https://127.0.0.1:19444/",
        role="negative-control",
        image="nginx@sha256:5ab5b0b01097420873a3f3330f44248e34a3c2a3e8d5ee30658aeae8cb7435da",
        supports_h2=False,
        probes=("h2_alpn",),
        notes="Same image; ALPN h2 must fail",
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
    "httpd-2.4.71": Target(
        id="httpd-2.4.71",
        name="Apache httpd 2.4.71 + mod_http2",
        url="https://127.0.0.1:19445/",
        role="cross-impl",
        image="httpd@sha256:32e9403360ab2f1047523e72f256527fb9aee68b342abf6ad03f0d629157f3d9",
        supports_h2=True,
        notes="Not expected to share nginx cleanup-overcredit bug",
        # Full pressure works on Apache (real PASS); keep defaults, allow soft fallback.
    ),
    "nginx-1.31.9": Target(
        id="nginx-1.31.9",
        name="nginx 1.31.9 (patched clean control)",
        url="https://127.0.0.1:19446/",
        role="patched-control",
        image="nginx@sha256:08f354a3b44c422021a5c0f5efb3e27f8f90236b5447d3bac4053f5f50ab6760",
        supports_h2=True,
        notes="Vendor fix for CVE-2026-123007",
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
    "caddy-2.10": Target(
        id="caddy-2.10",
        name="Caddy 2.10 (cross-impl)",
        url="https://127.0.0.1:19447/",
        role="cross-impl",
        image="caddy@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb",
        supports_h2=True,
        notes="Digest-pinned caddy:2.10; Go tls stack; full KU → Broken pipe",
        key_updates=0,
        carrier_app_bytes=200_000,
        fallback_key_updates=None,  # primary already the soft profile
        fallback_carrier_app_bytes=None,
    ),
    "envoy-1.32": Target(
        id="envoy-1.32",
        name="Envoy 1.32 (cross-impl)",
        url="https://127.0.0.1:19448/",
        role="cross-impl",
        image="envoyproxy/envoy@sha256:6bf0d37dd5e8eac4b37effe89a1aec4760f7f2ce860d1fd6af22147eb87a5058",
        supports_h2=True,
        notes="Digest-pinned envoy; direct_response (no Range); restart between runs",
        key_updates=0,
        carrier_app_bytes=200_000,
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
        restart_container="integer-lab-envoy",
    ),
    "go-nethttp": Target(
        id="go-nethttp",
        name="Go net/http HTTP/2 (stdlib demo)",
        url="https://127.0.0.1:19449/",
        role="cross-impl",
        image="golang@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac",
        supports_h2=True,
        notes="Built from pinned golang:1.24-bookworm; full KU → Broken pipe",
        key_updates=0,
        carrier_app_bytes=200_000,
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
    "nghttpd": Target(
        id="nghttpd",
        name="nghttpd (nghttp2 reference)",
        url="https://127.0.0.1:19450/",
        role="reference",
        image="debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc",
        supports_h2=True,
        notes="nghttpd from apt on pinned debian; no Range; full KU → Broken pipe",
        key_updates=0,
        carrier_app_bytes=200_000,
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
    "openlitespeed-1.9.4": Target(
        id="openlitespeed-1.9.4",
        name="OpenLiteSpeed 1.9.4 Open (not LSWS Enterprise)",
        url="https://127.0.0.1:19451/",
        role="cross-impl",
        image="litespeedtech/openlitespeed@sha256:48bc2719f24c4a451f13c379f499e9822f00aeae9ed248fea6d934d4a4231d50",
        supports_h2=True,
        notes=(
            "Open source OpenLiteSpeed (OLS). Commercial LSWS Enterprise is "
            "a different product and is not this image. Pinned "
            "litespeedtech/openlitespeed:1.9.4-lsphp82. lshttpd reports "
            "LiteSpeed/1.9.4 Open. HTTPS listener on container :443 with "
            "enableSpdy 8. WebAdmin 7080 is unpublished (disableWebAdmin 1). "
            "Static index supports Range. Soft profile (key_updates=0, "
            "carrier=200000). One run: cleanup_overcredit PASS (completed "
            "NOT_PROVEN; streams 149/151 had no RST; canary 0/10; no "
            "post-refund PING ACK; alive=False). wu_zero_stream and "
            "wu_stream_overflow are ANOMALY (stream RST, connection kept). "
            "settings_iw_overflow scored FAIL with no RST/GOAWAY. Those "
            "rows are review items. No new CVE is claimed"
        ),
        key_updates=0,
        carrier_app_bytes=200_000,
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
    "openresty-1.31.8.1": Target(
        id="openresty-1.31.8.1",
        name="OpenResty 1.31.8.1 (nginx 1.31.8 line)",
        url="https://127.0.0.1:19452/",
        role="nginx-family",
        image="openresty/openresty@sha256:2cb90d64192934c26b3749cf744f47edd59277787fe761bd109eeebdc3e2214a",
        supports_h2=True,
        notes=(
            "openresty/1.31.8.1 alpine is still nginx 1.31.8; full KeyUpdate "
            "pressure like nginx-1.31.8. A cleanup_overcredit FAIL is "
            "nginx-family inheritance of CVE-2026-123007, not a new CVE"
        ),
        # Same pressure as nginx-1.31.8. No soft fallback: ku=0 would hide
        # the known nginx-line accounting signal.
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
    "node-http2": Target(
        id="node-http2",
        name="Node.js http2 (stdlib)",
        url="https://127.0.0.1:19454/",
        role="cross-impl",
        image="node@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a",
        supports_h2=True,
        notes=(
            "Built from pinned node:22-alpine (v22.23.5); stdlib http2; "
            "soft profile like go/caddy (key_updates=0). Lab app is not "
            "separately hashed"
        ),
        key_updates=0,
        carrier_app_bytes=200_000,
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
    "haproxy-3.0": Target(
        id="haproxy-3.0",
        name="HAProxy 3.0.31 LTS (http-request return)",
        url="https://127.0.0.1:19453/",
        role="cross-impl",
        image="haproxy@sha256:7430e63d3052198b18a40665b59a5826bc428e8bceb0c561d82258149ef855ee",
        supports_h2=True,
        notes=(
            "Pinned haproxy:3.0-alpine (3.0.31 LTS). Single container: "
            "TLS+ALPN h2 and http-request return file (no backend, no Range). "
            "Soft profile (key_updates=0). One run: cleanup_overcredit PASS "
            "(completed NOT_PROVEN). settings_iw_overflow scored FAIL with "
            "no RST/GOAWAY on this return-file frontend; that is a review "
            "item, not a new CVE. Traefik was not selected"
        ),
        key_updates=0,
        carrier_app_bytes=200_000,
        fallback_key_updates=None,
        fallback_carrier_app_bytes=None,
    ),
}


def list_targets() -> list[Target]:
    return list(TARGETS.values())


def get_target(target_id: str) -> Target:
    try:
        return TARGETS[target_id]
    except KeyError as exc:
        known = ", ".join(TARGETS)
        raise KeyError(f"unknown target {target_id!r}; known: {known}") from exc
