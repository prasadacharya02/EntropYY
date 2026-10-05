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


socketio = SocketIO(app, async_mode="threading")  # same-origin only
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
        "tagline": "Multi-signal file-behaviour risk with a local tamper-evident audit ledger",
        "edition": "Command Platform",
        "version": "2.1.0",
        "dry_run": bool(config.DRY_RUN),
        "watch_folders": config.WATCH_FOLDERS,
        "ledger_mode": status.get("mode"),
        "is_blockchain": status.get("is_blockchain", False),
        "positioning": "Purple-team range for SOC training — not an EDR replacement",
    })


PIPELINE_STALE_SECONDS = 8.0


def pipeline_status() -> dict:
    hb = None
    try:
        db = get_db()
        try:
            hb = read_pipeline_heartbeat(db)
        finally:
            db.close()
    except Exception:
        log.exception("Pipeline status read failed")

    victim = os.path.abspath(config.VICTIM_USER_FILES)
    if not hb:
        return {
            "online": False, "age_seconds": None, "pid": None,
            "watch_folders": [], "watching_victim": False,
            "dry_run": None, "engine": None, "stats": {},
            "victim_folder": victim, "reason": "no pipeline heartbeat",
        }

    age = max(0.0, time.time() - float(hb["heartbeat"]))
    folders = [os.path.abspath(f) for f in hb.get("watch_folders", [])]
    watching_victim = any(
        victim == f or victim.startswith(f + os.sep) for f in folders
    )
    pid = hb.get("pid")
    pid_alive = False
    try:
        if pid and int(pid) > 0:
            os.kill(int(pid), 0)
            pid_alive = True
    except PermissionError:
        # EPERM means the PID exists but this process lacks signal rights.
        pid_alive = True
    except (OSError, TypeError, ValueError):
        pid_alive = False
    online = age <= PIPELINE_STALE_SECONDS and pid_alive
    reasons = []
    if age > PIPELINE_STALE_SECONDS:
        reasons.append("stale heartbeat")
    if not pid_alive:
        reasons.append("pipeline PID is not running")
    if not watching_victim:
        reasons.append("victim folder is not in the watch set")
    return {
        "online": online,
        "age_seconds": round(age, 1),
        "pid": pid,
        "pid_alive": pid_alive,
        "watch_folders": folders,
        "watching_victim": watching_victim,
        "dry_run": bool(hb.get("dry_run")),
        "engine": hb.get("engine"),
        "stats": hb.get("stats") or {},
        "victim_folder": victim,
        "reason": "; ".join(reasons) if reasons else None,
    }


@app.route("/api/pipeline")
def pipeline():
    return jsonify(pipeline_status())


@app.route("/api/health")
def health():
    pipeline = pipeline_status()
    return jsonify({"status": "ok", "service": "dashboard",
                    "pipeline_online": pipeline["online"],
                    "pipeline_reason": pipeline["reason"]})


def _physical_quarantine_count() -> int:
    q_dir = config.QUARANTINE_DIR
    if not os.path.isdir(q_dir):
        return 0
    return sum(
        1 for name in os.listdir(q_dir)
        if not name.endswith((".meta.json", ".tmp"))
        and os.path.isfile(os.path.join(q_dir, name))
    )


def _stats_payload() -> dict:
    db = get_db()
    try:
        row = db.execute("""
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN action >= 1 THEN 1 ELSE 0 END),0) AS threats,
                   COALESCE(SUM(CASE WHEN response_termination='TERMINATED' THEN 1 ELSE 0 END),0) AS terminated,
                   COALESCE(SUM(CASE WHEN response_quarantine='QUARANTINED' THEN 1 ELSE 0 END),0) AS quarantined_events,
                   COALESCE(SUM(CASE WHEN restore_result='RESTORED' THEN 1 ELSE 0 END),0) AS recovered,
                   AVG(entropy) AS avg_entropy,
                   MAX(entropy) AS max_entropy,
                   MAX(risk_score) AS max_risk
            FROM events
        """).fetchone()
    finally:
        db.close()
    return {
        "total": int(row["total"] or 0),
        "threats": int(row["threats"] or 0),
        "terminated": int(row["terminated"] or 0),
        "quarantined": _physical_quarantine_count(),
        "quarantined_events": int(row["quarantined_events"] or 0),
        "recovery": int(row["recovered"] or 0),
        "avg_entropy": round(float(row["avg_entropy"]), 2) if row["avg_entropy"] is not None else None,
        "max_entropy": round(float(row["max_entropy"]), 2) if row["max_entropy"] is not None else None,
        "max_risk": round(float(row["max_risk"]), 4) if row["max_risk"] is not None else None,
        "blockchain_tx": bc.get_event_count(),
    }


@app.route("/api/stats")
def stats():
    try:
        return jsonify(_stats_payload())
    except Exception:
        log.exception("Stats API failed")
        return _api_error()


@app.route("/api/telemetry", methods=["POST"])
def reject_telemetry():
    """Reject the retired attacker-to-dashboard synthetic telemetry path."""
    return jsonify({
        "error": "telemetry injection was removed; events are sourced from the monitored filesystem",
        "source": "monitoring.pipeline_runner",
    }), 410


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
            "fallback": "Local SQLite hash-chain ledger (tamper-evident; not a blockchain)",
            "none": "Offline — no ledger",
        }
        mode = status.get("mode", "none")
        return jsonify({
            "connected"      : connected,
            "is_blockchain"  : status.get("is_blockchain", connected),
            "mode"           : mode,
            "mode_label"     : labels.get(mode, mode),
            "tx_count"       : count,
            "ledger_integrity": status.get("ledger_integrity"),
            "is_tamper_evident": status.get("is_tamper_evident", False),
            "address"        : config.CONTRACT_ADDRESS,
            "network"        : config.GANACHE_URL
        })
    except Exception:
        log.exception("Blockchain status API failed")
        return _api_error("blockchain status unavailable")


@app.route("/api/intel/status")
def intelligence_status():
    """Expose actual local intelligence-registry contents and scope."""
    if not config.EXCHANGE_ENABLED:
        return jsonify({"enabled": False, "mode": "disabled",
                        "scope": "no exchange is configured"})
    registry = None
    try:
        from blockchain.behavioral_exchange import BehavioralIntelExchange
        from blockchain.fingerprint_exchange import get_exchange
        registry = BehavioralIntelExchange()
        return jsonify({
            "enabled": True,
            "scope": "local shared SQLite registry; not network-replicated",
            "behavioral": registry.stats(),
            "exact_content_hashes": get_exchange().count(),
            "behavioral_match_is_advisory": True,
        })
    except Exception:
        log.exception("Intelligence registry status failed")
        return _api_error("intelligence status unavailable")
    finally:
        if registry is not None:
            registry.close()


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
        return jsonify(_stats_payload())
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

                try:
                    live = _stats_payload()
                    live["time"] = datetime.now().strftime("%H:%M:%S")
                    live["pipeline"] = pipeline_status()
                    socketio.emit("live_update", live)
                except Exception:
                    log.exception("Live counters unavailable; update not emitted")
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
                "risk_score": None,
                "engine": None,
                "explanation": "",
                "factors": []
            })

        keys = row.keys()
        entropy = row["entropy"]
        delta   = row["entropy_delta"]
        action  = row["action"] or 0
        engine  = row["engine"] if "engine" in keys else None
        explanation = row["explanation"] if "explanation" in keys else ""
        risk_score = row["risk_score"] if "risk_score" in keys else None
        risk_percent = round(float(risk_score) * 100, 1) if risk_score is not None else None

        decisions = {
            0: "IGNORE",
            1: "ALERT",
            2: "TERMINATE",
            3: "TERMINATE + QUARANTINE"
        }
        outcome = row["outcome"] if "outcome" in keys and row["outcome"] else row["status"]

        factors = [
            {"name": "Engine", "value": engine, "pass": True},
            {"name": "Requested action", "value": decisions.get(action, "UNKNOWN"), "pass": action >= 1},
            {"name": "Outcome", "value": outcome or "not recorded", "pass": bool(outcome)},
            {"name": "Entropy", "value": f"{entropy:.2f}" if entropy is not None else "not measured", "pass": entropy is not None and entropy >= config.ENTROPY_THRESHOLD},
            {"name": "Entropy delta", "value": f"{abs(delta):.2f}" if delta is not None else "not measured", "pass": delta is not None and abs(delta) >= config.ENTROPY_DELTA_THRESHOLD},
        ]
        if risk_score is not None:
            factors.append({"name": "Uncalibrated risk index", "value": f"{risk_percent:.1f}/100", "pass": risk_score >= 0.45})
        if explanation:
            factors.append({"name": "Explanation", "value": explanation[:120], "pass": True})

        return jsonify({
            "decision": decisions.get(action, "UNKNOWN"),
            "risk_score": risk_percent,
            "engine": engine,
            "outcome": outcome,
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
        try:
            rows = db.execute("""
                SELECT process_name AS name, pid, COUNT(*) AS hits,
                       MAX(action) AS max_action, MAX(entropy) AS max_ent,
                       MAX(CASE WHEN response_termination='TERMINATED' THEN 1 ELSE 0 END) AS was_terminated
                FROM events
                WHERE action >= 1 AND pid IS NOT NULL AND process_name IS NOT NULL
                GROUP BY process_name, pid
                ORDER BY hits DESC
                LIMIT 10
            """).fetchall()
        finally:
            db.close()
        return jsonify([{
            "name": r["name"], "pid": r["pid"], "hits": r["hits"],
            "status": "killed" if r["was_terminated"] else "observed",
            "entropy": r["max_ent"],
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
        db = get_db()
        try:
            row = db.execute("""
                SELECT COUNT(*) AS count, MAX(risk_score) AS max_risk,
                       SUM(CASE WHEN action >= 3 THEN 1 ELSE 0 END) AS contained
                FROM events WHERE action >= 1
                  AND timestamp >= datetime('now', '-10 minutes')
            """).fetchone()
        finally:
            db.close()
        count = int(row["count"] or 0)
        risk = float(row["max_risk"] or 0.0)
        if count == 0:
            level, label = 0, "MINIMAL"
        else:
            level = round(100 * risk)
            label = "CRITICAL" if risk >= 0.85 else "ELEVATED" if risk >= 0.55 else "GUARDED"
        return jsonify({"level": level, "label": label,
                        "recent_threats": count,
                        "recent_critical": int(row["contained"] or 0),
                        "risk_method": "uncalibrated multi-signal evidence index"})
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