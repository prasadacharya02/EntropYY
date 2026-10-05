"""Stable, path-independent fingerprints of short file-operation sequences.

This is a compact similarity feature for controlled threat-intelligence
experiments. It is neither a malware binary signature nor a unique identifier,
and must not be used alone for a destructive response.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Iterable

_BITS = 64
_MASK = (1 << _BITS) - 1


def _ext_family(ext: str) -> str:
    ext = (ext or "").lower()
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"}:
        return "media"
    if ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv"}:
        return "document"
    if ext in {".zip", ".rar", ".7z", ".gz", ".bz2"}:
        return "archive"
    if ext in {".py", ".js", ".ts", ".java", ".c", ".cpp", ".go", ".rs"}:
        return "code"
    return "other"


def _rate_bucket(value) -> str:
    try:
        rate = max(0.0, float(value or 0.0))
    except (TypeError, ValueError):
        rate = 0.0
    if rate < 0.25:
        return "r0"
    if rate < 1.0:
        return "r1"
    if rate < 3.0:
        return "r2"
    return "r3"


def _entropy_bucket(value) -> str:
    try:
        entropy = max(0.0, min(8.0, float(value or 0.0)))
    except (TypeError, ValueError):
        entropy = 0.0
    return f"e{int(entropy * 2) / 2:.1f}"


def _delta_bucket(value) -> str:
    try:
        delta = float(value or 0.0)
    except (TypeError, ValueError):
        delta = 0.0
    return f"d{int(round(delta * 2)) / 2:+.1f}"


def event_token(event: dict) -> str:
    ext = event.get("file_extension") or Path(str(event.get("file_path") or "")).suffix
    structure = event.get("structure") or {}
    structure_tag = "bad" if event.get("structure_anomaly") or structure.get("anomaly") else "ok"
    return ":".join((
        str(event.get("event_type") or "UNKNOWN").upper(),
        _ext_family(ext),
        _entropy_bucket(event.get("entropy_overall")),
        _delta_bucket(event.get("entropy_delta")),
        _rate_bucket(event.get("events_per_sec")),
        "x1" if event.get("ext_changed") else "x0",
        structure_tag,
    ))


def _hash64(token: str) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")


def behavioral_fingerprint(events: Iterable[dict], *, max_events: int = 24) -> str:
    """Return a deterministic 64-bit SimHash over operation and n-gram tokens."""
    sequence = [event_token(event) for event in list(events)[-max_events:]]
    if not sequence:
        return ""
    weighted_tokens: list[tuple[str, float]] = []
    for index, token in enumerate(sequence):
        # Recent events are useful while still preserving prior campaign shape.
        weighted_tokens.append(("u:" + token, 1.0 + index / max(1, len(sequence) * 4)))
    for left, right in zip(sequence, sequence[1:]):
        weighted_tokens.append(("b:" + left + "|" + right, 1.4))
    if len(sequence) >= 3:
        for tri in zip(sequence, sequence[1:], sequence[2:]):
            weighted_tokens.append(("t:" + "|".join(tri), 1.6))

    votes = [0.0] * _BITS
    for token, weight in weighted_tokens:
        value = _hash64(token)
        for bit in range(_BITS):
            votes[bit] += weight if value & (1 << bit) else -weight
    result = 0
    for bit, vote in enumerate(votes):
        if vote >= 0:
            result |= 1 << bit
    return f"{result:016x}"


def hamming_distance(left: str, right: str) -> int:
    """Number of differing bits between two 64-bit hexadecimal signatures."""
    try:
        return ((int(left, 16) ^ int(right, 16)) & _MASK).bit_count()
    except (TypeError, ValueError):
        return _BITS


def similarity(left: str, right: str) -> float:
    return 1.0 - hamming_distance(left, right) / _BITS
