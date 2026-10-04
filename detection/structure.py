"""Lightweight, non-executing file-structure checks used as one weak signal.

This module never extracts archives or invokes a parser. Checks are deliberately
bounded to headers/trailers and archive directory metadata to avoid turning file
inspection into a decompression or parser-risk surface. A mismatch is evidence,
not a verdict: valid files can be unusual, truncated, or legitimately rewritten.
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path


_FORMATS = {
    ".pdf": "pdf",
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
    ".bmp": "bmp",
    ".webp": "webp",
    ".mp4": "mp4",
    ".mov": "mp4",
    ".zip": "zip",
    ".docx": "docx",
    ".xlsx": "xlsx",
    ".pptx": "pptx",
}


def _valid(expected: str, head: bytes, tail: bytes, path: str) -> tuple[bool, str]:
    if expected == "pdf":
        ok = head.startswith(b"%PDF-") and b"%%EOF" in tail
        return ok, "PDF header/trailer" if ok else "missing PDF header or EOF marker"
    if expected == "png":
        ok = head.startswith(b"\x89PNG\r\n\x1a\n") and b"IEND" in tail
        return ok, "PNG signature/trailer" if ok else "missing PNG signature or IEND marker"
    if expected == "jpeg":
        ok = head.startswith(b"\xff\xd8\xff") and tail.rstrip().endswith(b"\xff\xd9")
        return ok, "JPEG SOI/EOI markers" if ok else "missing JPEG SOI or EOI marker"
    if expected == "gif":
        ok = head.startswith((b"GIF87a", b"GIF89a")) and b";" in tail
        return ok, "GIF signature/trailer" if ok else "missing GIF signature or trailer"
    if expected == "bmp":
        ok = head.startswith(b"BM") and len(head) >= 14
        return ok, "BMP header" if ok else "missing BMP header"
    if expected == "webp":
        ok = head.startswith(b"RIFF") and head[8:12] == b"WEBP"
        return ok, "WebP RIFF header" if ok else "missing WebP RIFF header"
    if expected == "mp4":
        ok = len(head) >= 12 and head[4:8] == b"ftyp"
        return ok, "ISO base-media ftyp box" if ok else "missing ftyp box"
    if expected in {"zip", "docx", "xlsx", "pptx"}:
        try:
            if not zipfile.is_zipfile(path):
                return False, "missing ZIP central directory"
            if expected == "zip":
                return True, "ZIP central directory present"
            required = {
                "docx": {"[Content_Types].xml", "word/document.xml"},
                "xlsx": {"[Content_Types].xml", "xl/workbook.xml"},
                "pptx": {"[Content_Types].xml", "ppt/presentation.xml"},
            }[expected]
            with zipfile.ZipFile(path, "r") as archive:
                names = set(archive.namelist())
            missing = sorted(required - names)
            if missing:
                return False, "missing package parts: " + ", ".join(missing)
            return True, "Office ZIP package parts present"
        except (OSError, zipfile.BadZipFile, RuntimeError):
            return False, "invalid ZIP container"
    return True, "unvalidated"


def inspect_structure(path: str, *, original_path: str | None = None,
                      max_tail_bytes: int = 4096) -> dict:
    """Return a bounded structural check for formats with recognizable framing.

    When a renamed file has an opaque/known ransomware extension, the original
    suffix is checked as well. Unknown formats are explicitly reported as
    unchecked rather than treated as valid.
    """
    ext = Path(path).suffix.lower()
    expected = _FORMATS.get(ext)
    if expected is None and original_path:
        expected = _FORMATS.get(Path(original_path).suffix.lower())
    if expected is None:
        return {"checked": False, "format": None, "valid": None,
                "anomaly": False, "evidence": "format has no bounded signature check"}

    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            head = handle.read(32)
            if size > max_tail_bytes:
                handle.seek(max(0, size - max_tail_bytes))
            tail = handle.read(max_tail_bytes)
        valid, evidence = _valid(expected, head, tail, path)
        return {"checked": True, "format": expected, "valid": bool(valid),
                "anomaly": not bool(valid), "evidence": evidence}
    except OSError as exc:
        return {"checked": True, "format": expected, "valid": None,
                "anomaly": False, "evidence": f"structure read failed: {exc.__class__.__name__}"}
