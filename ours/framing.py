"""Minimal HTTP/2 framing helpers (raw bytes).

We deliberately do *not* use a full client library for WINDOW_UPDATE / SETTINGS
generation: stock stacks refuse or auto-correct the adversarial counter walks
that this lab needs to exercise. Encoding is RFC 9113 / RFC 7541 only.
"""

from __future__ import annotations

MAX_WINDOW = 0x7FFFFFFF
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA = 0
HEADERS = 1
RST_STREAM = 3
SETTINGS = 4
PING = 6
GOAWAY = 7
WINDOW_UPDATE = 8

END_STREAM = 0x1
ACK = 0x1
END_HEADERS = 0x4

PROTOCOL_ERROR = 1
FLOW_CONTROL_ERROR = 3
CANCEL = 8

# HPACK static-table indexes (RFC 7541 Appendix A)
IDX_AUTHORITY = 1
IDX_METHOD = 2
IDX_PATH = 4
IDX_RANGE = 50


def frame(kind: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes((kind, flags))
        + stream.to_bytes(4, "big")
        + payload
    )


def hpack_integer(value: int, prefix_bits: int, mask: int = 0) -> bytes:
    maximum = (1 << prefix_bits) - 1
    if value < maximum:
        return bytes((mask | value,))
    out = bytearray((mask | maximum,))
    value -= maximum
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_literal(name_index: int, value: str | bytes, indexed_name_bits: int = 4) -> bytes:
    if isinstance(value, str):
        value = value.encode()
    # Never-indexed literal with indexed name (prefix 4) — keeps dynamic table empty.
    return hpack_integer(name_index, indexed_name_bits, 0) + hpack_integer(len(value), 7) + value


def request_headers(authority: str, path: str = "/index.html", extra: bytes = b"") -> bytes:
    # Indexed :method GET (0x82), :scheme https (0x87).
    return (
        b"\x82\x87"
        + hpack_literal(IDX_AUTHORITY, authority)
        + hpack_literal(IDX_PATH, path)
        + extra
    )


def head_request_block(authority: str, path: str = "/index.html") -> bytes:
    return (
        hpack_literal(IDX_METHOD, "HEAD")
        + b"\x87"
        + hpack_literal(IDX_AUTHORITY, authority)
        + hpack_literal(IDX_PATH, path)
    )


def range_literal(start: int, end: int) -> bytes:
    return hpack_literal(IDX_RANGE, f"bytes={start}-{end}")


def headers_frame(stream: int, block: bytes, end_stream: bool = True) -> bytes:
    flags = END_HEADERS | (END_STREAM if end_stream else 0)
    return frame(HEADERS, flags, stream, block)


def get_request(stream: int, authority: str, path: str = "/index.html", extra: bytes = b"") -> bytes:
    return headers_frame(stream, request_headers(authority, path, extra), True)


def settings_initial_window(value: int) -> bytes:
    return frame(SETTINGS, 0, 0, b"\x00\x04" + value.to_bytes(4, "big"))


def settings_ack() -> bytes:
    return frame(SETTINGS, ACK, 0, b"")


def client_preface_settings() -> bytes:
    # HEADER_TABLE_SIZE=0, INITIAL_WINDOW_SIZE=65535
    payload = (
        b"\x00\x01\x00\x00\x00\x00"
        + b"\x00\x04\x00\x00\xff\xff"
    )
    return PREFACE + frame(SETTINGS, 0, 0, payload)


def window_update(stream: int, value: int) -> bytes:
    if not (1 <= value <= MAX_WINDOW):
        raise ValueError(f"WINDOW_UPDATE increment out of range: {value}")
    return frame(WINDOW_UPDATE, 0, stream, value.to_bytes(4, "big"))


def window_update_raw(stream: int, value: int) -> bytes:
    """Encode WINDOW_UPDATE without RFC validation (for zero / adversarial probes)."""
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError(f"raw WINDOW_UPDATE value out of u32 range: {value}")
    # Reserved high bit must be clear in the 31-bit increment field for legal frames;
    # for value 0 we still emit a well-formed 4-byte payload of zeros (RFC-illegal).
    return frame(WINDOW_UPDATE, 0, stream, (value & 0x7FFFFFFF).to_bytes(4, "big") if value <= MAX_WINDOW else value.to_bytes(4, "big"))


def ping(payload: bytes = b"INTBUG01") -> bytes:
    if len(payload) != 8:
        raise ValueError("PING payload must be 8 bytes")
    return frame(PING, 0, 0, payload)


def parse_frames(buf: bytes):
    """Yield (kind, flags, stream, payload) from a byte buffer; return remainder."""
    offset = 0
    frames = []
    while offset + 9 <= len(buf):
        length = int.from_bytes(buf[offset : offset + 3], "big")
        if offset + 9 + length > len(buf):
            break
        kind = buf[offset + 3]
        flags = buf[offset + 4]
        stream = int.from_bytes(buf[offset + 5 : offset + 9], "big") & MAX_WINDOW
        payload = buf[offset + 9 : offset + 9 + length]
        frames.append((kind, flags, stream, payload))
        offset += 9 + length
    return frames, buf[offset:]
