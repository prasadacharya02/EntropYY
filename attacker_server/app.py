from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from collections import deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
VICTIM_DIR = os.path.join(ROOT_DIR, "victim_server")
USER_FILES = os.path.join(VICTIM_DIR, "user_files")

HTML_PATH = os.path.join(
    BASE_DIR,
    "templates",
    "attacker.html",
)

sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, VICTIM_DIR)

import config
import ransomware_engines as engines

try:
    from create_fake_files import restore_all_files
except Exception:
    restore_all_files = None


# ============================================================
# Malware & Network Exploit Process Manager
# ============================================================

_proc_lock = threading.Lock()
_proc = None            # subprocess.Popen | None
_proc_family = None     # selected family id
_stream = deque(maxlen=300)
_control_path = os.path.join(ROOT_DIR, "attacker_control.json")

_KILLED_EXIT = 42

_SCAN_RE = re.compile(
    r"scan complete:\s*(\d+)\s*targets,\s*(\d+)\s*skipped"
)
_HIT_RE = re.compile(r"encrypted\s+(\d+)/(\d+)")
_NOTE_RE = re.compile(r"Note dropped:")
_BYTES_RE = re.compile(r"\((\d+)\s*bytes\)")


def _relay_telemetry(filename: str, family: str, pid: int = 292):
    """Sends real-time threat telemetry directly to SOC Server (5000)."""
    try:
        url = "http://127.0.0.1:5000/api/telemetry"
        payload = json.dumps({
            "filename": filename,
            "family": family,
            "entropy": 7.95,
            "action": 3,
            "pid": pid,
            "process_name": f"ransomware_{family}.exe"
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=0.8)
    except Exception:
        pass


def _write_control(payload):
    current = {}
    try:
        with open(_control_path, encoding="utf-8") as fh:
            current = json.load(fh)
    except (OSError, ValueError):
        pass
    current.update(payload)
    try:
        with open(_control_path, "w", encoding="utf-8") as fh:
            json.dump(current, fh)
    except OSError:
        pass


def _append_log(text: str):
    """Helper to append structured log entries."""
    timestamp = time.strftime("%H:%M:%S")
    entry = {
        "time": timestamp,
        "timestamp": timestamp,
        "msg": text,
        "text": text,
        "line": text
    }
    with _proc_lock:
        _stream.append(entry)


def _simulate_network_exploit(family_id: str):
    """Simulates initial access breach via unpatched SMB Port 445 (EternalBlue MS17-010)."""
    _append_log(f"[smb] Initializing Network Exploit Module (Target: victim-pc:445)...")
    time.sleep(0.4)
    _append_log(f"[smb] Scanning target ports: 135/tcp (RPC), 139/tcp (NetBIOS), 445/tcp (SMB)...")
    time.sleep(0.5)
    _append_log(f"[smb] Detected service: Windows SMBv1 (srv.sys Memory Corruption Vulnerability MS17-010)")
    time.sleep(0.5)
    _append_log(f"[smb] Crafting malicious SMB_COM_TRANSACTION2 buffer overflow packet...")
    time.sleep(0.4)
    _append_log(f"[smb] Transmitting kernel shellcode to target memory space...")
    time.sleep(0.5)
    _append_log(f"[smb] EXPLOIT SUCCESSFUL — Arbitrary kernel code execution achieved.")
    time.sleep(0.3)
    _append_log(f"[smb] Spawning high-privilege NT AUTHORITY\\SYSTEM payload process...")
    time.sleep(0.4)


def _stream_reader(proc):
    """Reads stdout lines and stores structured objects to prevent 'undefined undefined'."""
    try:
        for line in proc.stdout:
            text = line.rstrip("\n")
            if text:
                _append_log(text)

                if "encrypt" in text.lower() or "note" in text.lower() or "." in text:
                    filename = f"sample_{int(time.time() * 1000)}.{_proc_family or 'wncry'}"
                    parts = text.split()
                    for p in parts:
                        if "." in p and len(p) > 3:
                            filename = os.path.basename(p.strip("():,"))
                            break
                    _relay_telemetry(filename, _proc_family or "wannacry", proc.pid or 292)
    except (OSError, ValueError):
        pass
    finally:
        try:
            proc.wait(timeout=10)
        except Exception:
            pass


def _spawn(family_id):
    global _proc, _proc_family
    with _proc_lock:
        if _proc is not None and _proc.poll() is None:
            return False, f"{_proc_family} already running"
        _stream.clear()
        _write_control({"factor": 1.0, "paused": False})

        # Run SMB Port 445 Exploit sequence first
        _simulate_network_exploit(family_id)

        command = [
            sys.executable,
            "-m",
            "attacker_server.ransomware_engines",
            family_id,
            "--control",
            _control_path,
        ]
        _proc = subprocess.Popen(
            command,
            cwd=ROOT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _proc_family = family_id

    threading.Thread(
        target=_stream_reader, args=(_proc,), daemon=True
    ).start()

    # Trigger immediate batch telemetry on attack start
    for sample in ["Wedding_Photos.jpg", "Family_Vacation.jpg", "Tax_Returns.pdf", "Client_Notes.docx"]:
        _relay_telemetry(f"{sample}.{family_id}", family_id, _proc.pid if _proc else 292)

    return True, "ok"


def _child_state():
    with _proc_lock:
        proc = _proc
        family = _proc_family
        lines = list(_stream)

    if proc is None:
        return {
            "active": False, "family": None, "phase": "IDLE",
            "progress": 0, "log": lines, "pid": None,
            "defender_killed": False,
        }

    alive = proc.poll() is None
    last_entry = lines[-1] if lines else ""
    last_text = last_entry["msg"] if isinstance(last_entry, dict) else str(last_entry)

    targets = skipped = hit = total = notes = 0
    bytes_encrypted = 0
    for entry in lines:
        line = entry["msg"] if isinstance(entry, dict) else str(entry)
        m = _SCAN_RE.search(line)
        if m:
            targets, skipped = int(m.group(1)), int(m.group(2))
        m = _HIT_RE.search(line)
        if m:
            hit, total = int(m.group(1)), int(m.group(2))
        if _NOTE_RE.search(line):
            notes += 1
        m = _BYTES_RE.search(line)
        if m and "encrypting" in line:
            bytes_encrypted += int(m.group(1))

    defender_killed = ("TERMINATED BY DEFENSE" in last_text) or (
        (not alive) and proc.returncode == _KILLED_EXIT
    )

    if defender_killed:
        phase = "KILLED_BY_DEFENDER"
    elif alive:
        phase = (
            "PAUSED"
            if _read_control_or_default().get("paused")
            else "ENCRYPTING"
        )
    elif proc.returncode == 0:
        phase = "COMPLETED" if total else "STOPPED"
    else:
        phase = "STOPPED"

    return {
        "active": alive,
        "family": family,
        "phase": phase,
        "progress": round(min(100, hit / max(total, 1) * 100), 1) if total else 0,
        "targets": targets,
        "files_hit": hit,
        "files_skipped": skipped,
        "notes_dropped": notes,
        "bytes_encrypted": bytes_encrypted,
        "pid": proc.pid if alive else None,
        "returncode": proc.returncode,
        "defender_killed": defender_killed,
        "log": lines,
    }


def _read_control_or_default():
    try:
        with open(_control_path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _stop_child(operator: bool):
    with _proc_lock:
        proc = _proc
    if proc is None or proc.poll() is not None:
        return False
    try:
        proc.send_signal(signal.SIGINT if operator else signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return False
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    return True


def _reset_lab_estate():
    """Complete multi-service reset: stops attack, restores files, empties quarantine, resets DB."""
    _stop_child(operator=True)

    try:
        if restore_all_files is not None:
            restore_all_files()
        else:
            fixtures_script = os.path.join(VICTIM_DIR, "create_fake_files.py")
            if os.path.exists(fixtures_script):
                subprocess.run([sys.executable, fixtures_script, "--clean"], cwd=ROOT_DIR, capture_output=True)
    except Exception as exc:
        sys.stderr.write(f"[reset] Restore fixture error: {exc}\n")

    lock_extensions = (
        ".wncry", ".wncryt", ".ryk", ".maze", ".revil",
        ".lockbit", ".akira", ".clop", ".qilin", ".abcd"
    )
    note_markers = (
        "@please_read_me@", "ryukreadme", "restore-my-files", "recover-",
        "maze-readme", "revil-readme", "akira-readme", "clop-readme", "qilin-readme"
    )
    if os.path.exists(USER_FILES):
        for root_dir, _, filenames in os.walk(USER_FILES):
            for filename in filenames:
                f_lower = filename.lower()
                ext = os.path.splitext(f_lower)[1]
                if ext in lock_extensions or any(m in f_lower for m in note_markers):
                    try:
                        os.remove(os.path.join(root_dir, filename))
                    except Exception:
                        pass

    q_dir = getattr(config, "QUARANTINE_DIR", os.path.join(ROOT_DIR, "quarantine_storage"))
    if os.path.exists(q_dir):
        for item in os.listdir(q_dir):
            try:
                item_path = os.path.join(q_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
            except Exception:
                pass

    db_path = getattr(config, "DB_PATH", os.path.join(ROOT_DIR, "entropy.db"))
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("DELETE FROM events")
            conn.commit()
            conn.close()
        except Exception as exc:
            sys.stderr.write(f"[reset] DB clear error: {exc}\n")


def victim_snapshot():
    total = 0
    locked = 0
    notes = 0

    lock_extensions = (
        ".wncry", ".wncryt", ".ryk", ".maze", ".revil",
        ".lockbit", ".akira", ".clop", ".qilin", ".abcd"
    )

    note_markers = (
        "@please_read_me@", "ryukreadme", "restore-my-files", "recover-",
        "maze-readme", "revil-readme", "akira-readme", "clop-readme", "qilin-readme"
    )

    if not os.path.isdir(USER_FILES):
        return {"exists": False, "total": 0, "locked": 0, "notes": 0}

    for directory, _, filenames in os.walk(USER_FILES):
        for filename in filenames:
            total += 1
            extension = os.path.splitext(filename)[1].lower()
            lowercase_name = filename.lower()

            if extension in lock_extensions or (extension.startswith(".") and len(extension) == 8):
                locked += 1

            if any(marker in lowercase_name for marker in note_markers):
                notes += 1

    return {"exists": True, "total": total, "locked": locked, "notes": notes}


def read_json(handler):
    content_length = int(handler.headers.get("Content-Length") or 0)
    if content_length <= 0:
        return {}
    raw = handler.rfile.read(content_length)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def send_json(handler, payload, status=200):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def send_text(handler, text, content_type="text/plain; charset=utf-8"):
    body = text.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Content-Disposition", "attachment; filename=campaign.log")
    handler.end_headers()
    handler.wfile.write(body)


def send_html(handler):
    with open(HTML_PATH, "r", encoding="utf-8") as file:
        html = file.read()

    host_header = handler.headers.get("Host", "127.0.0.1:8001")
    host = host_header.split(":", 1)[0]
    forwarded_protocol = handler.headers.get("X-Forwarded-Proto")
    scheme = "https" if forwarded_protocol == "https" else "http"

    victim_url = config.PUBLIC_VICTIM_URL or f"{scheme}://{host}:5001"
    dashboard_url = config.PUBLIC_DASHBOARD_URL or f"{scheme}://{host}:5000"
    attacker_url = config.PUBLIC_ATTACKER_URL or f"{scheme}://{host}:8001"

    html = html.replace("__VICTIM_URL__", victim_url)
    html = html.replace("__DASHBOARD_URL__", dashboard_url)
    html = html.replace("__ATTACKER_URL__", attacker_url)
    html = html.replace("__CONTROL_TOKEN__", getattr(config, "CONTROL_TOKEN", ""))

    body = html.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def control_authorized(handler):
    configured_token = config.CONTROL_TOKEN
    if configured_token:
        supplied = handler.headers.get("Authorization", "")
        expected = f"Bearer {configured_token}"
        return hmac.compare_digest(supplied, expected)
    try:
        address = ipaddress.ip_address(handler.client_address[0])
        return address.is_loopback
    except ValueError:
        return False


_control_authorized = control_authorized


def send_forbidden(handler):
    send_json(
        handler,
        {"ok": False, "error": "control route requires local access or a valid bearer token"},
        status=403,
    )


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, format_string, *args):
        sys.stderr.write("[attacker] " + (format_string % args) + "\n")

    def do_GET(self):
        path = urlparse(self.path).path

        if path in {"/", "/index.html", "/attacker.html"}:
            send_html(self)
            return

        if path == "/api/families":
            send_json(self, engines.list_families())
            return

        if path == "/api/stats":
            stats = _child_state()
            stats["victim"] = victim_snapshot()
            send_json(self, stats)
            return

        if path == "/api/log":
            stats = _child_state()
            lines = [
                entry.get("msg", "") if isinstance(entry, dict) else str(entry)
                for entry in stats.get("log", [])
            ]
            send_text(self, "\n".join(lines) + "\n")
            return

        self.send_error(404, "not found")

    def do_POST(self):
        path = urlparse(self.path).path
        protected_routes = {"/api/launch", "/api/stop", "/api/pause", "/api/resume", "/api/speed", "/api/reset"}

        if path in protected_routes and not control_authorized(self):
            send_forbidden(self)
            return

        data = read_json(self)

        if path == "/api/launch":
            family = (data.get("family") or "").strip().lower()

            if family not in engines.FAMILIES:
                send_json(self, {"ok": False, "error": "unknown family"}, status=400)
                return

            snapshot = victim_snapshot()
            if not snapshot["exists"] or snapshot["total"] == 0:
                send_json(self, {"ok": False, "error": "victim folder is empty — hit RESET first"}, status=400)
                return

            current = _child_state()
            if current.get("active"):
                send_json(self, {"ok": False, "error": f"{current.get('family')} already running"}, status=409)
                return

            ok, message = _spawn(family)
            if not ok:
                send_json(self, {"ok": False, "error": message}, status=500)
                return

            send_json(self, {"ok": True, "family": family, "pid": _child_state()["pid"], "stats": _child_state()})
            return

        if path == "/api/stop":
            stopped = _stop_child(operator=True)
            send_json(self, {"ok": True, "stopped": bool(stopped)})
            return

        if path == "/api/pause":
            state = _child_state()
            ok = bool(state.get("active"))
            if ok: _write_control({"paused": True})
            send_json(self, {"ok": ok, "paused": ok})
            return

        if path == "/api/resume":
            state = _child_state()
            ok = bool(state.get("active"))
            if ok: _write_control({"paused": False})
            send_json(self, {"ok": ok, "paused": False})
            return

        if path == "/api/speed":
            try:
                factor = float(data.get("factor", 1.0))
                speed = min(5.0, max(0.1, factor))
                _write_control({"factor": speed})
                send_json(self, {"ok": True, "speed_factor": speed})
            except (TypeError, ValueError):
                send_json(self, {"ok": False, "error": "invalid speed"}, status=400)
            return

        if path == "/api/reset":
            _reset_lab_estate()
            send_json(self, {"ok": True, "victim": victim_snapshot()})
            return

        self.send_error(404, "not found")


if __name__ == "__main__":
    if not os.path.isfile(HTML_PATH):
        print(f"MISSING: {HTML_PATH}")
        raise SystemExit(1)

    print("=" * 60)
    print("  ATTACKER SITE")
    print("  http://0.0.0.0:8001")
    print("=" * 60)

    server = ThreadingHTTPServer(("0.0.0.0", 8001), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAttacker server stopped")
        server.shutdown()
        server.server_close()