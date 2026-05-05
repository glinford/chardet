"""Stage 1a: BOM (Byte Order Mark) detection."""

from __future__ import annotations

from chardet.pipeline import DetectionResult

# Ordered longest-first so UTF-32 is checked before UTF-16
# (UTF-32-LE BOM starts with the same bytes as UTF-16-LE BOM)
_BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xfe\xff", "utf-16"),
    (b"\xff\xfe", "utf-16"),
)

_UTF32_BOMS: frozenset[bytes] = frozenset({b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00"})


def detect_bom(data: bytes) -> DetectionResult | None:
    """Check for a byte order mark at the start of *data*.

    :param data: The raw byte data to examine.
    :returns: A :class:`DetectionResult` with confidence 1.0, or ``None``.
    """
    for bom_bytes, encoding in _BOMS:
        if data.startswith(bom_bytes):
            # UTF-32 BOMs overlap with UTF-16 BOMs (e.g. FF FE 00 00 starts
            # with the UTF-16-LE BOM FF FE).  Validate that the payload after
            # a UTF-32 BOM is a valid number of UTF-32 code units (multiple of
            # 4 bytes).  If not, skip to let the shorter UTF-16 BOM match.
            if bom_bytes in _UTF32_BOMS:
                payload_len = len(data) - len(bom_bytes)
                if payload_len % 4 != 0:
                    continue
            return DetectionResult(encoding=encoding, confidence=1.0, language=None)
    return None























"""Early detection of escape-sequence-based encodings (ISO-2022, HZ-GB-2312, UTF-7).

These encodings use ESC (0x1B), tilde (~), or plus (+) sequences to switch
character sets.  They must be detected before binary detection (ESC is a control
byte) and before ASCII detection (HZ-GB-2312 and UTF-7 use only printable ASCII
bytes plus their respective shift markers).

Note: ``from __future__ import annotations`` is intentionally omitted because
this module is compiled with mypyc, which does not support PEP 563 string
annotations.
"""

from chardet.pipeline import DETERMINISTIC_CONFIDENCE, DetectionResult


def _has_valid_hz_regions(data: bytes) -> bool:
    """Check that at least one ~{...~} region contains valid GB2312 byte pairs.

    In HZ-GB-2312 GB mode, characters are encoded as pairs of bytes in the
    0x21-0x7E range.  We require at least one region with a non-empty, even-
    length run of such bytes.
    """
    start = 0
    while True:
        begin = data.find(b"~{", start)
        if begin == -1:
            return False
        end = data.find(b"~}", begin + 2)
        if end == -1:
            return False
        region = data[begin + 2 : end]
        # Must be non-empty, even length, and all bytes in GB2312 range
        if (
            len(region) >= 2
            and len(region) % 2 == 0
            and all(0x21 <= b <= 0x7E for b in region)
        ):
            return True
        start = end + 2


# Base64 alphabet used inside UTF-7 shifted sequences (+<Base64>-)
_B64_CHARS: bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_UTF7_BASE64: frozenset[int] = frozenset(_B64_CHARS)

# Lookup table mapping each Base64 byte to its 6-bit value (0-63).
_B64_DECODE: dict[int, int] = {c: i for i, c in enumerate(_B64_CHARS)}


def _is_valid_utf7_b64(b64_bytes: bytes) -> bool:
    """Check if base64 bytes decode to valid UTF-16BE with correct padding.

    A valid UTF-7 shifted sequence must:
    1. Contain at least 3 Base64 characters (18 bits, enough for one 16-bit
       UTF-16 code unit).
    2. Have zero-valued trailing padding bits (the unused low bits of the last
       Base64 sextet after the last complete 16-bit code unit).
    3. Decode to valid UTF-16BE — no lone surrogates.

    This rejects accidental ``+<alphanum>-`` patterns found in URLs, MIME
    boundaries, hex-encoded hashes (e.g. SHA-1 git refs), and other ASCII data.

    The caller (``_has_valid_utf7_sequences``) already checks ``b64_len >= 3``
    before calling this function, so *b64_bytes* is always at least 3 bytes.
    """
    n = len(b64_bytes)
    total_bits = n * 6
    # Check that padding bits (trailing bits after last complete code unit)
    # are zero.
    padding_bits = total_bits % 16
    if padding_bits > 0:
        last_val = _B64_DECODE[b64_bytes[-1]]
        # The low `padding_bits` of the last sextet must be zero
        mask = (1 << padding_bits) - 1
        if last_val & mask:
            return False
    # Decode the base64 to raw bytes and validate as UTF-16BE.
    # Lone surrogates (unpaired 0xD800-0xDFFF code units) are illegal in
    # well-formed UTF-16 and cannot appear in real UTF-7 text.  This catches
    # hex-encoded hashes and other accidental base64-like sequences.
