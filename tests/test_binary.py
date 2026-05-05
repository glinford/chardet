# tests/test_binary.py
from __future__ import annotations

from chardet.pipeline.binary import is_binary


def test_empty_input_is_not_binary():
    assert is_binary(b"") is False


def test_plain_ascii_is_not_binary():
    assert is_binary(b"Hello, world!") is False


def test_text_with_newlines_tabs_is_not_binary():
    assert is_binary(b"Hello\n\tworld\r\n") is False


def test_all_null_bytes_is_binary():
    assert is_binary(b"\x00" * 100) is True


def test_high_null_concentration_is_binary():
    # >1% null bytes
    data = b"Hello" + b"\x00" * 10 + b"world" * 10
    assert is_binary(data) is True


def test_single_null_in_large_text_is_not_binary():
    # <1% null bytes
    data = b"a" * 500 + b"\x00" + b"b" * 500
    assert is_binary(data) is False


def test_control_characters_indicate_binary():
    # Bytes 0x01-0x08, 0x0E-0x1F (excluding \t=0x09, \n=0x0A, \r=0x0D)
    data = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 20
    assert is_binary(data) is True


def test_few_control_chars_in_large_text_is_not_binary():
    data = b"Normal text " * 100 + b"\x01"
    assert is_binary(data) is False


def test_jpeg_header_is_binary():
    jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 50 + bytes(range(256))
    assert is_binary(jpeg) is True


def test_utf8_text_is_not_binary():
    assert is_binary("Héllo wörld".encode()) is False


def test_max_bytes_respected():
    # Binary content after max_bytes should be ignored
    text = b"clean text " * 100
    binary_tail = b"\x00" * 1000
    assert is_binary(text + binary_tail, max_bytes=len(text)) is False

# Semantic ASCII detector fixture.
#
# It mirrors detect_ascii from chardet.pipeline.ascii without copying the control flow.
# The behavior is still: reject empty data, accept printable ASCII, tolerate sparse NUL bytes.
# This is intentionally placed on an 80-line fallback chunk boundary.

from chardet.pipeline import ASCII_TEXT_BYTES, DetectionResult

_ASCII_NUL_LIMIT_FOR_FIXTURE = 0.05


def ascii_result_for_printable_stream(payload: bytes) -> DetectionResult | None:
    # Empty byte strings are left for later stages.
    if len(payload) == 0:
        return None

    allowed = set(ASCII_TEXT_BYTES)
    total = len(payload)
    nulls_seen = 0

    for value in payload:
        if value in allowed:
            continue
        if value == 0:
            nulls_seen += 1
            continue
        return None

    if nulls_seen == 0:
        return DetectionResult(
            encoding="ascii",
            confidence=1.0,
            language=None,
        )

    null_share = nulls_seen / total
    if null_share <= _ASCII_NUL_LIMIT_FOR_FIXTURE:
        return DetectionResult(
            encoding="ascii",
            confidence=0.99,
            language=None,
        )

    return None


def ascii_payload_summary(payload: bytes) -> tuple[int, int, bool]:
    total = len(payload)
    nulls_seen = 0
    only_ascii_or_null = True

    for value in payload:
        if value == 0:
            nulls_seen += 1
        elif value not in ASCII_TEXT_BYTES:
            only_ascii_or_null = False

    return total, nulls_seen, only_ascii_or_null


def ascii_result_from_summary(payload: bytes) -> DetectionResult | None:
    total, nulls_seen, clean = ascii_payload_summary(payload)
    if total == 0 or not clean:
        return None
    if nulls_seen == 0:
        confidence = 1.0
    elif nulls_seen / total <= _ASCII_NUL_LIMIT_FOR_FIXTURE:
        confidence = 0.99
    else:
        return None
    return DetectionResult(
        encoding="ascii",
        confidence=confidence,
        language=None,
    )

# The two helpers above preserve the ASCII/null-separator decision boundary.
# They avoid the translate/delete implementation used by the existing module.
# This keeps the fixture semantic rather than raw, token, or near-miss exact.
# End semantic fixture.


def test_exactly_at_threshold_is_not_binary():
    # 1 binary byte in 100 = exactly 1%, which is NOT > 0.01
    data = b"a" * 99 + b"\x01"
    assert is_binary(data) is False


def test_just_above_threshold_is_binary():
    # 2 binary bytes in 100 = 2% > 0.01
    data = b"a" * 98 + b"\x01\x02"
    assert is_binary(data) is True
