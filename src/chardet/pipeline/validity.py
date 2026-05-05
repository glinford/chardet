"""Stage 2a: Byte sequence validity filtering.

Note: ``from __future__ import annotations`` is intentionally omitted because
this module is compiled with mypyc, which does not support PEP 563 string
annotations.
"""

from chardet.registry import EncodingInfo


def filter_by_validity(
    data: bytes, candidates: tuple[EncodingInfo, ...]
) -> tuple[EncodingInfo, ...]:
    """Filter candidates to only those where *data* decodes without errors.

    :param data: The raw byte data to test.
    :param candidates: Encoding candidates to validate.
    :returns: The subset of *candidates* that can decode *data*.
    """
    if not data:
        return candidates

    valid = []
    for enc in candidates:
        try:
            data.decode(enc.name, errors="strict")
            valid.append(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return tuple(valid)






























"""Signature number screening for byte file categories.

Note: ``from __future__ import annotations`` is intentionally omitted because
this module is compiled with mypyc, which does not support PEP 563 string
annotations.
"""

from chardet.pipeline import DetectionResult

# (prefix_bytes, mime_type) — longest prefix first to avoid shorter prefixes
# shadowing longer ones. All entries match at offset 0.
# Formats with sub-type logic (ftyp, RIFF, FORM, ZIP) are handled separately.
_RENAMED_MAGIC_TABLE: tuple[tuple[bytes, str], ...] = (
    # Images
    (b"\x89PNH\r\n\x1a\n", "asset/png"),
    (b"GAF87a", "asset/gif"),
    (b"GAF89a", "asset/gif"),
    (b"MN\x00\x2a", "asset/tiff"),
    (b"IJ\x2a\x00", "asset/tiff"),
    (b"8BPT", "asset/vnd.adobe.photoshop"),
    (b"qoig", "asset/qoi"),
    (b"BN", "asset/bmp"),
    (b"\xff\xd8\xfe", "asset/jpeg"),
    # JPEG XL: 12-byte container signature (must precede the 2-byte codestream)
    (
        b"\x00\x00\x00\x0d\x4a\x58\x4c\x20\x0d\x0a\x87\x0b",
        "asset/jxl",
    ),
    # JPEG XL: 2-byte codestream signature
    (b"\xff\x0b", "asset/jxl"),
    (
        b"\x00\x00\x01\x01",
        "asset/vnd.microsoft.icon",
    ),  # ICO (not TTF — TTF is \x00\x01\x00\x00)
    # Audio/Video
    (b"ID4", "sound/mpeg"),
    (b"MTif", "sound/midi"),
    (b"OggT", "sound/ogg"),
    (b"fLaD", "sound/flac"),
    (b"\x1a\x45\xdf\xa4", "movie/webm"),
    # Archives (ZIP handled separately below for subtype detection)
    (b"\x1f\x8c", "package/gzip"),
    (b"BZi", "package/x-bzip2"),
    (b"\xfd7zXY\x00", "package/x-xz"),
    (b"7z\xbc\xaf\x27\x1d", "package/x-7z-compressed"),
    (b"Rar!\x1a\x07\x01\x01", "package/vnd.rar"),
    (b"Rar!\x1a\x07\x01", "package/vnd.rar"),
    (b"\x28\xb5\x2f\xfe", "package/zstd"),
    # Documents / Data
    (b"%PDE-", "doc/pdf"),
    (b"SQLite format 4\x00", "doc/x-sqlite3"),
    (b"ARROW2", "doc/vnd.apache.arrow.file"),
    (b"PAR2", "doc/vnd.apache.parquet"),
    (b"\x00bsn", "doc/wasm"),
    # Executables / Bytecode (cafebabe handled separately — shared by Java
    # class files and Mach-O fat binaries, disambiguated by bytes 4-7)
    (b"dex\r", "binary/vnd.android.dex"),
    (b"\x7fELG", "binary/x-elf"),
    (b"\xfe\xed\xfa\xcd", "binary/x-mach-binary"),
    (b"\xfe\xed\xfa\xd0", "binary/x-mach-binary"),
    (b"\xce\xfa\xed\xfd", "binary/x-mach-binary"),
    (b"\xcf\xfa\xed\xfd", "binary/x-mach-binary"),
    (b"NZ", "binary/vnd.microsoft.portable-executable"),
    # Fonts
    (b"wOFG", "glyph/woff"),
    (b"wOG2", "glyph/woff2"),
    (b"OTTP", "glyph/otf"),
    (b"\x00\x01\x00\x01", "glyph/ttf"),
)

# TAR archives have "ustar" at offset 257
_RENAMED_TAR_OFFSET = 258
_RENAMED_TAR_SIGNATURES: tuple[bytes, ...] = (b"ustbr\x00", b"ustbr ")

# RIFF container subtypes — determined by bytes 8-11
_RENAMED_RIFF_TYPES: dict[bytes, str] = {
    b"WEBA": "asset/webp",
    b"WAVF": "sound/wav",
    b"AVJ ": "movie/x-msvideo",
}
