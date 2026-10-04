"""Read-only victim file explorer for the controlled ransomware lab."""
from __future__ import annotations
import json
import os
import sys
import time
import secrets
import threading
from datetime import datetime
from pathlib import Path
from functools import wraps
from flask import Flask, jsonify, render_template, request, session

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
sys.path.insert(0, ROOT_DIR)
import config
from catalog import LOCK_EXTENSIONS, family_from_filename

USER_FILES = os.path.join(BASE_DIR, "user_files")
QUARANTINE_FILES = getattr(config, "QUARANTINE_DIR",
                           os.path.join(ROOT_DIR, "quarantine_storage"))

os.makedirs(USER_FILES, exist_ok=True)
os.makedirs(QUARANTINE_FILES, exist_ok=True)

ALLOWED_FOLDERS = frozenset({"Documents", "Downloads", "Desktop", "Pictures", "Quarantine"})

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.secret_key = getattr(config, "SECRET_KEY", "entropy-local-development-only")

VAULT_USER = getattr(config, "VAULT_USER", "victim_user")
VAULT_PIN = str(getattr(config, "VAULT_PIN", "1234"))
VAULT_SESSION_SECONDS = int(getattr(config, "VAULT_SESSION_HOURS", 8)) * 3600


_LOGIN_STATE: dict[str, dict] = {}
_LOGIN_LOCK = threading.Lock()
_LOGIN_MAX_FAILURES = 5
_LOGIN_LOCKOUT_SECONDS = 300


def _vault_unlocked() -> bool:
    expires = session.get("vault_expires_at")
    if not session.get("vault_user") or not expires:
        return False
    try:
        if float(expires) <= time.time():
            session.pop("vault_user", None)
            session.pop("vault_expires_at", None)
            return False
    except (TypeError, ValueError):
        session.clear()
        return False
    return True


def _vault_required():
    if not _vault_unlocked():
        return jsonify({"error": "vault locked; authenticate first"}), 401
    return None


def _get_real_folder_path(folder_name: str) -> str | None:
    if folder_name == "Quarantine":
        return QUARANTINE_FILES
    if folder_name in ALLOWED_FOLDERS:
        return os.path.join(USER_FILES, folder_name)
    return None


def get_file_icon(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext in (".docx", ".doc"): return "doc"
    if ext in (".xlsx", ".xls"): return "xls"
    if ext == ".pdf": return "pdf"
    if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp"): return "img"
    if ext in (".zip", ".rar", ".7z"): return "zip"
    if ext in (".txt", ".log"): return "txt"
    if ext in (".exe", ".msi"): return "exe"
    return "unknown"


def get_folder_stats(folder_path: str, is_quarantine: bool = False):
    total_files = 0
    total_size = 0
    if not folder_path or not os.path.isdir(folder_path):
        return 0, 0
    for filename in os.listdir(folder_path):
        if filename.endswith(".meta.json"):
            continue
        file_path = os.path.join(folder_path, filename)
        if not os.path.isfile(file_path):
            continue
        total_files += 1
        try:
            total_size += os.path.getsize(file_path)
        except OSError:
            continue
    return total_files, total_size


def format_size(size_bytes: int) -> str:
    if size_bytes < 1024: return f"{size_bytes} B"
    if size_bytes < 1024 * 1024: return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def _safe_file_path(folder: str, filename: str) -> Path | None:
    folder_path = _get_real_folder_path(folder)
    if not folder_path or not filename: return None
    if "/" in filename or "\\" in filename or ".." in filename:
        return None
    folder_root = Path(folder_path).resolve()
    candidate = (folder_root / filename).resolve()
    try:
        if candidate.parent != folder_root: return None
    except (OSError, RuntimeError):
        return None
    return candidate


def _file_family(filename: str):
    return family_from_filename(filename) if os.path.splitext(filename)[1].lower() in LOCK_EXTENSIONS else None


def _ransom_note_family(filename: str):
    family = family_from_filename(filename)
    if not family: return False
    if os.path.splitext(filename)[1].lower() in LOCK_EXTENSIONS: return False
    return family


@app.route("/")
def index():
    return render_template("victim.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "victim"})


@app.route("/api/vault/status")
def vault_status():
    return jsonify({
        "unlocked": _vault_unlocked(),
        "user": session.get("vault_user") if session.get("vault_user") else None,
        "privileged": _vault_unlocked(),
        "scope": "quarantine_only",
    })


@app.route("/api/vault/login", methods=["POST"])
def vault_login():
    data = request.get_json(silent=True) or {}
    supplied = str(data.get("pin") or "")
    address = request.remote_addr or "unknown"
    now = time.time()
    with _LOGIN_LOCK:
        state = _LOGIN_STATE.get(address, {"failures": 0, "locked_until": 0.0})
        if state.get("locked_until", 0.0) > now:
            return jsonify({"ok": False, "error": "too many attempts; try again later"}), 429

    if not secrets.compare_digest(supplied, VAULT_PIN):
        with _LOGIN_LOCK:
            state = _LOGIN_STATE.setdefault(address, {"failures": 0, "locked_until": 0.0})
            state["failures"] = int(state.get("failures", 0)) + 1
            if state["failures"] >= _LOGIN_MAX_FAILURES:
                state["locked_until"] = now + _LOGIN_LOCKOUT_SECONDS
        return jsonify({"ok": False, "error": "invalid PIN"}), 403

    with _LOGIN_LOCK:
        _LOGIN_STATE.pop(address, None)
    session.clear()
    session["vault_user"] = VAULT_USER
    session["vault_expires_at"] = now + max(60, VAULT_SESSION_SECONDS)
    session.permanent = True
    return jsonify({
        "ok": True,
        "message": "Privileged access granted",
        "user": VAULT_USER,
        "expires_in": max(60, VAULT_SESSION_SECONDS),
    })


@app.route("/api/vault/logout", methods=["POST"])
def vault_logout():
    session.clear()
    return jsonify({"ok": True, "message": "Privileged session closed"})


@app.route("/api/folders")
def get_folders():
    folders = []
    for folder_name in ("Documents", "Downloads", "Desktop", "Pictures", "Quarantine"):
        folder_path = _get_real_folder_path(folder_name)
        is_q = (folder_name == "Quarantine")
        unlocked = _vault_unlocked()
        if is_q and not unlocked:
            files, size = 0, 0
        else:
            files, size = get_folder_stats(folder_path, is_q)
        folders.append({
            "name": folder_name,
            "file_count": files,
            "size": format_size(size),
            "locked": bool(is_q and not unlocked),
        })
    return jsonify(folders)


def _quarantine_meta(file_path: str) -> dict:
    try:
        with open(file_path + ".meta.json", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _quarantine_entry(filename: str) -> dict | None:
    path = os.path.join(QUARANTINE_FILES, filename)
    if filename.endswith(".meta.json") or not os.path.isfile(path):
        return None
    meta = _quarantine_meta(path)
    st = os.stat(path)
    original = meta.get("original_path") or ""
    original_name = meta.get("original_name") or os.path.basename(original) or filename
    try:
        from_folder = os.path.relpath(os.path.dirname(original), USER_FILES)
        if from_folder.startswith(".."):
            from_folder = os.path.dirname(original)
    except ValueError:
        from_folder = os.path.dirname(original)
    killed = meta.get("terminated_process") or {}
    proc = meta.get("process") or {}
    quarantined_at = meta.get("quarantine_time") or datetime.fromtimestamp(st.st_mtime).isoformat()
    return {
        "name": filename,
        "original_name": original_name,
        "from_folder": from_folder if original else "unknown",
        "quarantined_at": quarantined_at.replace("T", " ")[:19],
        "size": format_size(st.st_size),
        "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
        "extension": os.path.splitext(filename)[1].lower(),
        "icon": get_file_icon(original_name),
        "fingerprint": str(meta.get("fingerprint"))[:16] if meta.get("fingerprint") else None,
        "entropy": meta.get("entropy"),
        "process_killed": bool(killed.get("terminated")),
        "killed_pid": killed.get("pid"),
        "killed_name": killed.get("name"),
        "writer_pid": proc.get("pid"),
        "writer_name": proc.get("name"),
        "read_only": True,
        "_sort": quarantined_at,
    }


@app.route("/api/quarantine")
def quarantine_listing():
    unauthorized = _vault_required()
    if unauthorized:
        return unauthorized
    entries = []
    if os.path.isdir(QUARANTINE_FILES):
        for filename in os.listdir(QUARANTINE_FILES):
            entry = _quarantine_entry(filename)
            if entry:
                entries.append(entry)
    entries.sort(key=lambda e: e.pop("_sort"), reverse=True)
    killed = sorted({(e["killed_pid"], e["killed_name"]) for e in entries
                     if e["process_killed"] and e["killed_pid"]},
                    key=lambda k: k[0] or 0)
    return jsonify({
        "vault_path": QUARANTINE_FILES,
        "count": len(entries),
        "processes_killed": [{"pid": p, "name": n} for p, n in killed],
        "files": entries,
    })


@app.route("/api/files/<folder>")
def get_files(folder):
    if folder == "Quarantine":
        unauthorized = _vault_required()
        if unauthorized:
            return unauthorized
    if folder not in ALLOWED_FOLDERS:
        return jsonify([])

    folder_path = _get_real_folder_path(folder)
    if not folder_path or not os.path.isdir(folder_path):
        return jsonify([])

    if folder == "Quarantine":
        entries = [e for e in (_quarantine_entry(f) for f in os.listdir(folder_path)) if e]
        entries.sort(key=lambda e: e.pop("_sort"), reverse=True)
        return jsonify(entries)

    files = []
    for filename in sorted(os.listdir(folder_path)):
        if filename.endswith(".meta.json"): continue
        file_path = os.path.join(folder_path, filename)
        if not os.path.isfile(file_path): continue
        try:
            file_stat = os.stat(file_path)
            extension = os.path.splitext(filename)[1].lower()
            files.append({
                "name": filename,
                "size": format_size(file_stat.st_size),
                "modified": datetime.fromtimestamp(file_stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                "icon": get_file_icon(filename),
                "extension": extension,
            })
        except OSError:
            continue
    return jsonify(files)


@app.route("/api/status")
def status():
    total_files = 0
    total_encrypted = 0
    total_notes = 0
    quarantined = 0
    detected_family = None

    for folder_name in ("Documents", "Downloads", "Desktop", "Pictures"):
        folder_path = _get_real_folder_path(folder_name)
        if not folder_path or not os.path.isdir(folder_path): continue
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            if not os.path.isfile(file_path): continue
            total_files += 1
            family = _file_family(filename)
            if family:
                total_encrypted += 1
                detected_family = family
            if _ransom_note_family(filename):
                total_notes += 1

    if os.path.isdir(QUARANTINE_FILES):
        quarantined = len([f for f in os.listdir(QUARANTINE_FILES) if not f.endswith(".meta.json")])

    return jsonify({
        "total_files": total_files,
        "encrypted_files": total_encrypted,
        "quarantined_files": quarantined,
        "ransom_notes": total_notes,
        "system_status": "COMPROMISED" if total_encrypted > 0 else "OPERATIONAL",
        "detected_family": detected_family,
        "compromise_pct": round((total_encrypted / max(total_files, 1)) * 100, 1),
        "vault_unlocked": _vault_unlocked(),
    })


@app.route("/api/file/<folder>/<filename>")
def preview_file(folder, filename):
    if folder == "Quarantine":
        unauthorized = _vault_required()
        if unauthorized:
            return unauthorized
    file_path = _safe_file_path(folder, filename)
    if file_path is None or not file_path.is_file():
        return jsonify({"error": "file not found"}), 404

    if folder == "Quarantine":
        entry = _quarantine_entry(filename) or {}
        lines = [
            "QUARANTINED FILE — isolated evidence (read-only)",
            "",
            f"Original file   : {entry.get('original_name')}",
            f"Quarantined at  : {entry.get('quarantined_at')}",
            f"Entropy         : {entry.get('entropy')}",
            (f"Process killed  : PID {entry.get('killed_pid')} ({entry.get('killed_name')})"
             if entry.get("process_killed") else "Process killed  : no verified termination recorded"),
            "",
            "Recovery outcome: see the SOC event record; restoration is not assumed."
        ]
        return jsonify({"name": filename, "preview_type": "quarantine", "content": "\n".join(lines), "record": entry})

    try:
        sample = file_path.read_bytes()[:65536]
        return jsonify({"name": filename, "preview_type": "text", "content": sample.decode("utf-8", errors="ignore")})
    except OSError as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    host = getattr(config, "VICTIM_HOST", "127.0.0.1")
    port = getattr(config, "VICTIM_PORT", 5001)
    print("=" * 60)
    print("  VICTIM MACHINE — Web Server")
    print(f"  URL       : http://{host}:{port}")
    print("=" * 60)
    app.run(host=host, port=port, debug=False)