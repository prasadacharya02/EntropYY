"""Interpretable, multi-family event risk assessment.

Scores are evidence weights, not calibrated probabilities.  They are exposed
separately from the response action; only hard-confirmation rules and the
campaign layer may request containment.  This prevents an attractive score
from being misrepresented as statistical confidence.
"""
from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Iterable

import config


def _clip(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


# Evidence families that say something happened to THIS file's content or
# integrity.
#
# Deliberately excluded:
#   * velocity / scope — burst_rate, multi_file_scope, rename_activity,
#     verified_writer_context.  A bulk copy, a backup run or a report
#     generator produces all of them; alerting on them flooded the SOC
#     with 170 alerts for 200 clean files (measured).
#   * history-derived signals — repeated_format_anomaly, behavioral_intel
#     (matched but unconfirmed).  These are computed over recent *other*
#     files, so a clean file created shortly after a campaign inherits the
#     campaign's evidence and would be alerted for existing at the wrong
#     moment (measured: a benign post-incident probe scored 0.90).
#
# They still contribute to the risk index; they just cannot, alone,
# escalate an event to an operator alert.  Only damage attributable to
# the event itself does that.
CONTENT_EVIDENCE_FAMILIES = frozenset({
    "entropy_change",
    "high_entropy_context",
    "format_integrity",
    "extension_transition",
    "ransom_note",
    "defense_tamper",
})


def _family(ext: str) -> str:
    ext = (ext or "").lower()
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"}:
        return "media"
    if ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv"}:
        return "document"
    if ext in {".zip", ".rar", ".7z", ".gz", ".bz2", ".xz"}:
        return "archive"
    if ext in {".py", ".js", ".ts", ".java", ".c", ".cpp", ".go", ".rs"}:
        return "code"
    return "other"


class RiskEngine:
    """Assess an event with temporal, content and integrity evidence."""

    def __init__(self, history_size: int = 64):
        self.history = deque(maxlen=history_size)

    def reset(self) -> None:
        self.history.clear()

    def assess(self, event: dict, history: Iterable[dict] | None = None) -> dict:
        prior = list(self.history if history is None else history)
        path = str(event.get("file_path") or "")
        recent = [item for item in prior if item.get("file_path") != path]
        entropy = float(event.get("entropy_overall") or 0.0)
        delta = float(event.get("entropy_delta") or 0.0)
        rate = float(event.get("events_per_sec") or 0.0)
        in_window = int(event.get("events_in_window") or 0)
        ext = str(event.get("file_extension") or Path(path).suffix).lower()
        known_range = config.NORMAL_ENTROPY_RANGES.get(ext)

        # High entropy on a format expected to be compressed is deliberately
        # weak. The entropy-change signal is stronger than the absolute level.
        entropy_change = _clip(max(0.0, delta) / max(2.0 * config.ENTROPY_DELTA_THRESHOLD, 0.5)) * 0.82
        if entropy_change >= 0.18:
            entropy_change = max(0.0, min(0.90, entropy_change))
        high_entropy = 0.0
        if entropy >= config.ENTROPY_THRESHOLD:
            if known_range and entropy <= known_range[1] + 0.5:
                high_entropy = 0.08
            else:
                high_entropy = _clip((entropy - config.ENTROPY_THRESHOLD + 0.25) / 1.25) * 0.30

        structural = bool(event.get("structure_anomaly") or
                          (event.get("structure") or {}).get("anomaly"))
        anomalous_recent = {
            str(item.get("file_path") or "")
            for item in recent[-32:]
            if item.get("structure_anomaly") or
               (item.get("structure") or {}).get("anomaly")
        }
        if structural and path:
            anomalous_recent.add(path)
        structure_repeat = len(anomalous_recent)
        structure_signal = 0.58 if structural else 0.0
        repeated_structure = 0.0
        if structure_repeat >= 2:
            repeated_structure = min(0.88, 0.60 + 0.12 * (structure_repeat - 2))

        ext_change = 0.56 if event.get("ext_changed") else 0.0
        rename_signal = 0.12 if str(event.get("event_type") or "").upper() == "RENAMED" else 0.0
        speed_signal = _clip(rate / max(config.FILES_PER_SECOND_THRESHOLD, 0.1)) * 0.48
        distinct_recent = {
            str(item.get("file_path") or "")
            for item in recent[-32:]
            if str(item.get("event_type") or "").upper() in {"CREATED", "MODIFIED", "RENAMED"}
        }
        if path and str(event.get("event_type") or "").upper() in {"CREATED", "MODIFIED", "RENAMED"}:
            distinct_recent.add(path)
        scope_signal = _clip(max(0, len(distinct_recent) - 1) / 5.0) * 0.42
        burst_signal = max(speed_signal, _clip(max(0, in_window - 3) / 15.0) * 0.40)

        process = event.get("process") or {}
        verified_writer = bool(isinstance(process, dict) and process.get("identity_verified"))
        # Verified identity is context only; no process is considered malicious
        # merely because it wrote a file.
        process_context = 0.08 if verified_writer and (ext_change or structural) else 0.0

        known_behavioral = event.get("behavioral_match") or {}
        if not isinstance(known_behavioral, dict):
            known_behavioral = {}
        intel_signal = (0.62 if known_behavioral.get("confirmed") else
                        0.26 if known_behavioral.get("matched") else 0.0)

        signals = {
            "entropy_change": entropy_change,
            "high_entropy_context": high_entropy,
            "format_integrity": structure_signal,
            "repeated_format_anomaly": repeated_structure,
            "extension_transition": ext_change,
            "rename_activity": rename_signal,
            "burst_rate": burst_signal,
            "multi_file_scope": scope_signal,
            "verified_writer_context": process_context,
            "behavioral_intel": intel_signal,
            "ransom_note": 1.0 if event.get("ransom_note") else 0.0,
            "defense_tamper": 1.0 if event.get("defense_tamper") else 0.0,
        }
        # Combine distinct evidence families using noisy-OR. This is an
        # interpretable risk index, NOT a calibrated probability.
        risk = 1.0
        for value in signals.values():
            risk *= 1.0 - _clip(value)
        risk = 1.0 - risk
        supporting = [name for name, value in signals.items() if value >= 0.30]
        result = {
            "risk_score": round(_clip(risk), 4),
            "risk_label": ("high" if risk >= 0.75 else "elevated" if risk >= 0.45 else "low"),
            "risk_method": "uncalibrated_noisy_or_evidence_index",
            "risk_evidence": [name for name, value in signals.items() if value > 0],
            "risk_families": supporting,
            "structure_repeat_count": structure_repeat,
        }
        self.history.append(dict(event))
        return result
