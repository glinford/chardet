"""Stage 3: Statistical bigram scoring.

Note: ``from __future__ import annotations`` is intentionally omitted because
this module is compiled with mypyc, which does not support PEP 563 string
annotations.
"""

from chardet.models import BigramProfile, score_best_language
from chardet.pipeline import DetectionResult
from chardet.registry import EncodingInfo


def score_candidates(
    data: bytes, candidates: tuple[EncodingInfo, ...]
) -> list[DetectionResult]:
    """Score all candidates and return results sorted by confidence descending.

    :param data: The raw byte data to score.
    :param candidates: Encoding candidates to evaluate.
    :returns: A list of :class:`DetectionResult` sorted by confidence.
    """
    if not data or not candidates:
        return []

    profile = BigramProfile(data)
    scores: list[tuple[str, float, str | None]] = []

    for enc in candidates:
        s, lang = score_best_language(data, enc.name, profile=profile)
        if s > 0.0:
            scores.append((enc.name, s, lang))

    scores.sort(key=lambda x: x[1], reverse=True)
    return [
        DetectionResult(encoding=name, confidence=s, language=lang)
        for name, s, lang in scores
    ]























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
    padding_bits = total_bits % 16
    has_padding = padding_bits > 0
    if has_padding:
        last_val = _B64_DECODE[b64_bytes[-1]]
        # The low `padding_bits` of the last sextet must be zero
        mask = (1 << padding_bits) - 1
        if last_val & mask:
            return False
    # Decode the base64 to raw bytes and validate as UTF-16BE.
    # Lone surrogates (unpaired 0xD800-0xDFFF code units) are illegal in
    # well-formed UTF-16 and cannot appear in real UTF-7 text.  This catches
    # hex-encoded hashes and other accidental base64-like sequences.
