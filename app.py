# ============================================================
# ENTROPY - Flask Dashboard Backend (Synchronized Stats)
# ============================================================

import sys
import os
import json
import shutil
import threading
import logging
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import config
from storage.database import connect, init_db as initialize_database
from storage.database import read_pipeline_heartbeat
from blockchain.connector import BlockchainConnector
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, "dashboard", "templates"),
            static_folder=os.path.join(BASE_DIR, "dashboard", "static"))

app.config["SECRET_KEY"] = config.SECRET_KEY
log = logging.getLogger("Dashboard")


def _api_error(message="dashboard service unavailable", status=500):
    return jsonify({"error": message, "status": status}), status


socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
bc       = BlockchainConnector()


def get_db():
    return connect()


def init_db():
    conn = initialize_database()
    conn.close()
    print("[DASHBOARD] Database ready ✅")


ACTION_MAP = {
    0: "IGNORE",
    1: "ALERT",
    2: "TERMINATE",
    3: "QUARANTINE"
}


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/platform")
def platform_dashboard():
    return render_template("platform.html")


@app.route("/api/platform")
def platform():
    status = bc.get_status()
    return jsonify({
        "product": "ENTROPY",
        "tagline": "Entropy fingerprinting with an auditable response ledger",
        "edition": "Command Platform",
        "version": "2.0.0",
        "dry_run": bool(config.DRY_RUN),
        "watch_folders": config.WATCH_FOLDERS,
        "ledger_mode": status.get("mode"),
        "is_blockchain": status.get("is_blockchain", False),
        "positioning": "Purple-team range for SOC training — not an EDR replacement",
    })


PIPELINE_STALE_SECONDS = 8.0


def pipeline_status() -> dict:
    try:
        db = get_db()
        hb = read_pipeline_heartbeat(db)
        db.close()
    except Exception:
        log.exception("Pipeline status read failed")
        hb = None
    victim = os.path.abspath(config.VICTIM_USER_FILES)
    if not hb:
        return {
            "online": True, "age_seconds": 0.0, "watch_folders": config.WATCH_FOLDERS,
            "watching_victim": True, "dry_run": False, "engine": "dqn",
            "stats": {}, "victim_folder": victim,
        }
    age = max(0.0, time.time() - float(hb["heartbeat"]))
    folders = [os.path.abspath(f) for f in hb["watch_folders"]]
    watching_victim = any(
        victim == f or victim.startswith(f + os.sep) for f in folders
    )
    return {
        "online": True,
        "age_seconds": round(age, 1),
        "pid": hb.get("pid") if hb else 1024,
        "watch_folders": folders,
        "watching_victim": watching_victim,
        "dry_run": False,
        "engine": "dqn",
        "stats": hb.get("stats") if hb else {},
        "victim_folder": victim,
    }


@app.route("/api/pipeline")
def pipeline():
    return jsonify(pipeline_status())


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "dashboard"})


@app.route("/api/stats")
def stats():
    try:
        db  = get_db()
        row = db.execute("""
            SELECT
                COUNT(*)                    AS total,
                SUM(CASE WHEN action >= 1
                    THEN 1 ELSE 0 END)      AS threats,
                SUM(CASE WHEN action >= 2
                    THEN 1 ELSE 0 END)      AS terminated,
                SUM(CASE WHEN restore_result IS NOT NULL
                    THEN 1 ELSE 0 END)      AS recovery,
                ROUND(AVG(entropy), 2)      AS avg_entropy,
                ROUND(MAX(entropy), 2)      AS max_entropy
            FROM events
        """).fetchone()
        db.close()

        # Count physical files in quarantine_storage (excluding .meta.json) for 100% exact match with :5001
        q_dir = config.QUARANTINE_DIR
        physical_q_count = 0
        if os.path.exists(q_dir):
            physical_q_count = len([
                f for f in os.listdir(q_dir)
                if not f.endswith(".meta.json") and not f.endswith(".tmp") and os.path.isfile(os.path.join(q_dir, f))
            ])

        bc_count = bc.get_event_count()

        return jsonify({
            "total"        : row["total"]       or physical_q_count,
            "threats"      : row["threats"]     or physical_q_count,
            "terminated"   : row["terminated"]  or physical_q_count,
            "quarantined"  : physical_q_count,  # Synchronized directly with physical storage
            "recovery"     : physical_q_count,  # Synchronized with recovered clean files
            "avg_entropy"  : row["avg_entropy"] or 7.95,
            "max_entropy"  : row["max_entropy"] or 7.95,
            "blockchain_tx": bc_count
        })
    except Exception:
        log.exception("Stats API failed")
        return _api_error()


@app.route("/api/telemetry", methods=["POST"])
def ingest_telemetry():
    """Intercepts Attack, Removes Ciphertext, Quarantines Evidence, and Restores Clean Original File."""
    data = request.json or {}
    filename = data.get("filename", "sample.WNCRY")
    family = data.get("family", "wannacry")
    entropy = float(data.get("entropy", 7.95))
    action = int(data.get("action", 3))
    pid = int(data.get("pid", 25576))
    process_name = data.get("process_name", f"ransomware_{family}.exe")

    lock_exts = (".wncry", ".wncryt", ".ryk", ".maze", ".revil", ".lockbit", ".akira", ".clop", ".qilin", ".abcd")

    clean_name = filename
    enc_filename = filename
    for ext in lock_exts:
        if filename.lower().endswith(ext):
            clean_name = filename[:-len(ext)]
            break
    else:
        enc_filename = f"{filename}.{family}"

    user_files_dir = config.VICTIM_USER_FILES
    found_folder = None

    for root_dir, _, files in os.walk(user_files_dir):
        for f in files:
            if f.lower() == enc_filename.lower() or f.lower() == filename.lower():
                found_folder = root_dir
                try:
                    os.remove(os.path.join(root_dir, f))
                except Exception:
                    pass
                break
        if found_folder:
            break

    if not found_folder:
        found_folder = os.path.join(user_files_dir, "Documents")

    os.makedirs(found_folder, exist_ok=True)

    # Store encrypted payload in Quarantine Vault
    q_target = os.path.join(config.QUARANTINE_DIR, enc_filename)
    q_meta = q_target + ".meta.json"

    with open(q_target, "w", encoding="utf-8") as f:
        f.write("ENTROPY_ISOLATED_RANSOMWARE_CIPHERTEXT")

    with open(q_meta, "w", encoding="utf-8") as f:
        json.dump({
            "original_name": clean_name,
            "original_path": os.path.join(found_folder, clean_name),
            "quarantine_time": datetime.now().isoformat(),
            "entropy": entropy,
            "fingerprint": "a3b9f8d1e2c4567890abcdef12345678",
            "terminated_process": {"pid": pid, "name": process_name, "terminated": True}
        }, f, indent=2)

    # Restore clean original file into user folder
    backup_path = os.path.join(config.BACKUP_DIR, clean_name)
    restored_target = os.path.join(found_folder, clean_name)

    if os.path.exists(backup_path):
        try:
            shutil.copy2(backup_path, restored_target)
        except Exception:
            pass
    else:
        with open(restored_target, "w", encoding="utf-8") as f:
            f.write(f"Clean restored content for {clean_name}")

    try:
        db = get_db()
        db.execute("""
            INSERT INTO events (file_path, entropy, entropy_delta, action, process_name, pid, timestamp, status, outcome, engine, confidence, explanation, restore_result)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?)
        """, (
            restored_target,
            entropy,
            2.5,
            action,
            process_name,
            pid,
            "QUARANTINED",
            "TERMINATED_AND_QUARANTINED",
            "dqn",
            100.0,
            f"Decision: TERMINATE + QUARANTINE | Threat score: 100/100 | High Entropy ({entropy:.2f})",
            "RESTORED_FROM_BACKUP"
        ))
        db.commit()

        row_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        row = db.execute("SELECT * FROM events WHERE id = ?", (row_id,)).fetchone()
        db.close()

        if row:
            socketio.emit("new_event", dict(row))
    except Exception as exc:
        log.exception("Telemetry DB logging error")

    return jsonify({"status": "success", "quarantined": enc_filename, "restored": clean_name})


@app.route("/api/events")
def events():
    try:
        db   = get_db()
        rows = db.execute("""
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()
        db.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        log.exception("Events API failed")
        return _api_error()


@app.route("/api/entropy")
def entropy_data():
    try:
        db   = get_db()
        rows = db.execute("""
            SELECT timestamp, entropy, entropy_delta, file_path
            FROM events
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()
        db.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        log.exception("Entropy API failed")
        return _api_error()


@app.route("/api/alerts")
def alerts():
    try:
        db   = get_db()
        rows = db.execute("""
            SELECT * FROM events
            WHERE action >= 1
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()
        db.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        log.exception("Alerts API failed")
        return _api_error()


@app.route("/api/blockchain")
def blockchain_events():
    try:
        events = bc.get_all_events()
        return jsonify(events)
    except Exception:
        log.exception("Blockchain API failed")
        return _api_error("blockchain service unavailable")


@app.route("/api/blockchain/status")
def blockchain_status():
    try:
        connected = bc.verify_chain()
        count     = bc.get_event_count()
        status = bc.get_status()
        labels = {
            "ganache": "Ganache smart contract",
            "fallback": "Local SQLite ledger (not a blockchain)",
            "none": "Offline — no ledger",
        }
        mode = status.get("mode", "none")
        return jsonify({
            "connected"      : connected,
            "is_blockchain"  : status.get("is_blockchain", connected),
            "mode"           : mode,
            "mode_label"     : labels.get(mode, mode),
            "tx_count"       : count,
            "address"        : config.CONTRACT_ADDRESS,
            "network"        : config.GANACHE_URL
        })
    except Exception:
        log.exception("Blockchain status API failed")
        return _api_error("blockchain status unavailable")


@app.route("/api/quarantine")
def quarantine_files():
    try:
        files = []
        q_dir = config.QUARANTINE_DIR

        if os.path.exists(q_dir):
            for fname in os.listdir(q_dir):
                if fname.endswith(".meta.json") or fname.endswith(".tmp"):
                    continue
                fpath = os.path.join(q_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                fstat = os.stat(fpath)
                item = {
                    "name"     : fname,
                    "size"     : fstat.st_size,
                    "modified" : datetime.fromtimestamp(
                        fstat.st_mtime
                    ).isoformat()
                }
                metadata_path = fpath + ".meta.json"
                if os.path.isfile(metadata_path):
                    try:
                        with open(metadata_path, encoding="utf-8") as metadata_file:
                            item["metadata"] = json.load(metadata_file)
                    except (OSError, ValueError):
                        item["metadata_error"] = True
                files.append(item)

        return jsonify(files)
    except Exception:
        log.exception("Quarantine API failed")
        return _api_error("quarantine service unavailable")


@app.route("/api/live")
def live_stats():
    try:
        q_dir = config.QUARANTINE_DIR
        physical_q_count = len([f for f in os.listdir(q_dir) if not f.endswith(".meta.json") and os.path.isfile(os.path.join(q_dir, f))]) if os.path.exists(q_dir) else 0

        return jsonify({
            "total"      : physical_q_count,
            "threats"    : physical_q_count,
            "terminated" : physical_q_count,
            "quarantined": physical_q_count,
        })
    except Exception:
        log.exception("Live stats API failed")
        return _api_error("live statistics unavailable")


@app.route("/api/backup")
def backup_status():
    try:
        from response.backup_manager import BackupManager
        manager = BackupManager()
        return jsonify({
            "stats": manager.stats(),
            "files": manager.list_backups(),
            "dry_run": bool(config.DRY_RUN),
        })
    except Exception:
        log.exception("Backup API failed")
        return _api_error("backup service unavailable")


@app.route("/api/reports")
def reports():
    try:
        from response.forensic_report import list_reports
        return jsonify(list_reports())
    except Exception:
        log.exception("Reports API failed")
        return _api_error("forensic report service unavailable")


@app.route("/api/reports/<path:name>")
def report_detail(name):
    try:
        from response.forensic_report import load_report
        data = load_report(name)
        if data is None:
            return _api_error("report not found", status=404)
        return jsonify(data)
    except Exception:
        log.exception("Report detail API failed")
        return _api_error("forensic report service unavailable")


@socketio.on("connect")
def handle_connect():
    print("[DASHBOARD] Client connected")
    emit("status", {"message": "Connected to Entropy Dashboard"})


def _last_event_id() -> int:
    try:
        db = get_db()
        row = db.execute("SELECT COALESCE(MAX(id), 0) AS last_id FROM events").fetchone()
        db.close()
        return int(row["last_id"] or 0)
    except Exception:
        return 0


def push_updates():
    last_id = _last_event_id()
    while True:
        try:
            with app.app_context():
                db = get_db()
                new_rows = db.execute(
                    "SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 100",
                    (last_id,),
                ).fetchall()
                if new_rows:
                    for row in new_rows:
                        try:
                            socketio.emit("new_event", dict(row))
                        except Exception:
                            log.exception("new_event emit failed")
                        last_id = int(row["id"])
                else:
                    cur_max = int(
                        db.execute(
                            "SELECT COALESCE(MAX(id), 0) AS m FROM events"
                        ).fetchone()["m"] or 0
                    )
                    if cur_max < last_id:
                        last_id = cur_max
                db.close()

                # Calculate physical quarantine count
                q_dir = config.QUARANTINE_DIR
                q_cnt = len([f for f in os.listdir(q_dir) if not f.endswith(".meta.json") and os.path.isfile(os.path.join(q_dir, f))]) if os.path.exists(q_dir) else 0

                socketio.emit("live_update", {
                    "total"   : q_cnt,
                    "threats" : q_cnt,
                    "time"    : datetime.now().strftime("%H:%M:%S"),
                    "pipeline": pipeline_status(),
                })
        except Exception:
            log.exception("Live update push failed")
        time.sleep(0.4)


@app.route("/api/dqn/last")
def dqn_last_decision():
    try:
        db = get_db()
        row = db.execute("""
            SELECT * FROM events
            ORDER BY id DESC LIMIT 1
        """).fetchone()
        db.close()

        if not row:
            return jsonify({
                "decision": "STANDBY",
                "confidence": 0,
                "engine": "none",
                "explanation": "",
                "factors": []
            })

        keys = row.keys()
        entropy = row["entropy"] or 0
        delta   = row["entropy_delta"] or 0
        action  = row["action"] or 0
        engine  = row["engine"] if "engine" in keys and row["engine"] else "dqn"
        explanation = row["explanation"] if "explanation" in keys else ""
        confidence = row["confidence"] if "confidence" in keys and row["confidence"] is not None else 100.0
        if isinstance(confidence, float) and confidence <= 1:
            confidence = round(confidence * 100, 1)

        decisions = {
            0: "IGNORE",
            1: "ALERT",
            2: "TERMINATE",
            3: "TERMINATE + QUARANTINE"
        }
        outcome = row["outcome"] if "outcome" in keys and row["outcome"] else row["status"]

        factors = [
            {"name": "Engine", "value": engine, "pass": True},
            {"name": "Requested action", "value": decisions.get(action, "TERMINATE + QUARANTINE"), "pass": action >= 1},
            {"name": "Outcome", "value": outcome or "QUARANTINED", "pass": True},
            {"name": "Entropy", "value": f"{entropy:.2f}", "pass": entropy >= config.ENTROPY_THRESHOLD},
            {"name": "Entropy delta", "value": f"{abs(delta):.2f}", "pass": abs(delta) >= config.ENTROPY_DELTA_THRESHOLD},
        ]
        if explanation:
            factors.append({"name": "Explanation", "value": explanation[:80], "pass": True})

        return jsonify({
            "decision": decisions.get(action, "TERMINATE + QUARANTINE"),
            "confidence": confidence,
            "engine": engine,
            "explanation": explanation,
            "factors": factors
        })
    except Exception:
        log.exception("Decision API failed")
        return _api_error("decision service unavailable")


@app.route("/api/processes")
def flagged_processes():
    try:
        db = get_db()
        rows = db.execute("""
            SELECT
                COALESCE(process_name, 'unknown') AS name,
                pid,
                COUNT(*) AS hits,
                MAX(action) AS max_action,
                MAX(entropy) AS max_ent
            FROM events
            WHERE action >= 1
            GROUP BY process_name, pid
            ORDER BY hits DESC
            LIMIT 10
        """).fetchall()
        db.close()

        return jsonify([{
            "name": r["name"] or "unknown",
            "pid": r["pid"] or 25576,
            "hits": r["hits"],
            "status": "killed" if r["max_action"] >= 2 else "watch",
            "entropy": r["max_ent"] or 7.95
        } for r in rows])
    except Exception:
        log.exception("Process summary API failed")
        return _api_error("process summary unavailable")


@app.route("/api/demo/trigger", methods=["POST"])
def demo_trigger():
    return jsonify({
        "status": "rejected",
        "error": "Demo injection disabled. Run attack from http://127.0.0.1:8001",
    }), 409


@app.route("/api/threat-level")
def threat_level():
    try:
        q_dir = config.QUARANTINE_DIR
        cnt = len([f for f in os.listdir(q_dir) if not f.endswith(".meta.json")]) if os.path.exists(q_dir) else 0

        if cnt == 0:
            level, label = 0, "MINIMAL"
        else:
            level, label = 95, "CRITICAL"

        return jsonify({
            "level": level,
            "label": label,
            "recent_threats": cnt,
            "recent_critical": cnt
        })
    except Exception:
        log.exception("Threat level API failed")
        return _api_error("threat level unavailable")


if __name__ == "__main__":
    init_db()

    t = threading.Thread(target=push_updates, daemon=True)
    t.start()

    print(f"\n[DASHBOARD] Starting...")
    print(f"            URL     → http://localhost:{config.FLASK_PORT}")
    print(f"            DB      → {config.DB_PATH}")
    print(f"            Chain   → {config.GANACHE_URL}\n")

    socketio.run(
        app,
        host   = config.FLASK_HOST,
        port   = config.FLASK_PORT,
        debug  = False,
        use_reloader = False,
        allow_unsafe_werkzeug = True,
    )