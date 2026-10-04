# blockchain/connector.py
# ============================================================
# ENTROPY - Blockchain Connector
#
# Handles all Web3 communication with Ganache and the
# ThreatLogger smart contract.
#
# Features:
# - Non-blocking event logging (background thread)
# - Auto-reconnection on connection drop
# - Detailed error reporting
#
# FALLBACK MODE:
# If Ganache is not reachable (e.g. running a demo on a machine
# without a local Ethereum node) and config.BLOCKCHAIN_FALLBACK
# is enabled, the connector transparently falls back to a local
# SQLite ledger. This keeps the dashboard fully functional and
# lets the "on-chain" ledger be demonstrated without external
# infrastructure. The fallback is clearly labelled so it is never
# mistaken for a real public chain.
# ============================================================

import json
import os
import hashlib
import sqlite3
import sys
import time
import logging
import threading
from datetime import datetime
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

log = logging.getLogger("Blockchain")


class LocalLedger:
    """Append-only local hash-chain audit ledger (not an Ethereum chain).

    The previous-record hash links every row. This detects accidental or
    unsophisticated edits/deletions when checked against the current head. It
    is not tamper-proof against an administrator who can rewrite the entire
    database and recompute every hash; external anchoring is needed for that.
    """

    GENESIS = "0" * 64
    FIELDS = ("id", "fingerprint", "threatType", "timestamp", "pid",
              "entropy", "processName", "filePath", "actionTaken", "status")

    def __init__(self, path: str):
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT,
                threatType  TEXT,
                timestamp   INTEGER,
                pid         INTEGER,
                entropy     INTEGER,
                processName TEXT,
                filePath    TEXT,
                actionTaken TEXT,
                status      TEXT,
                prev_hash   TEXT,
                record_hash TEXT
            )
        """)
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(ledger)")}
        for name in ("prev_hash", "record_hash"):
            if name not in columns:
                self.conn.execute(f"ALTER TABLE ledger ADD COLUMN {name} TEXT")
        self.conn.execute("CREATE TABLE IF NOT EXISTS ledger_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.conn.commit()
        self._lock = threading.RLock()
        self._integrity_error = None
        self._initialize_hashes_if_legacy()
        log.info("[AUDIT] Local SQLite hash-chain ledger ready; not a blockchain")

    @classmethod
    def _record_hash(cls, fields: dict) -> str:
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _row_fields(self, row) -> dict:
        return {name: row[name] for name in self.FIELDS}

    def _verify_rows(self, rows=None) -> tuple[bool, str | None]:
        if rows is None:
            rows = self.conn.execute(
                "SELECT * FROM ledger ORDER BY id ASC"
            ).fetchall()
        previous = self.GENESIS
        expected_id = None
        for row in rows:
            if row["prev_hash"] != previous:
                return False, f"previous hash mismatch at ledger row {row['id']}"
            if expected_id is not None and int(row["id"]) <= expected_id:
                return False, "ledger IDs are not strictly increasing"
            expected_id = int(row["id"])
            actual = self._record_hash(self._row_fields(row))
            if not row["record_hash"] or row["record_hash"] != actual:
                return False, f"record hash mismatch at ledger row {row['id']}"
            previous = row["record_hash"]
        return True, None

    def _initialize_hashes_if_legacy(self) -> None:
        initialized = self.conn.execute(
            "SELECT value FROM ledger_meta WHERE key='hash_chain_initialized'"
        ).fetchone()
        rows = self.conn.execute("SELECT * FROM ledger ORDER BY id ASC").fetchall()
        if initialized:
            ok, error = self._verify_rows(rows)
            if not ok:
                self._integrity_error = error
            return
        if not rows:
            self.conn.execute(
                "INSERT INTO ledger_meta(key,value) VALUES('hash_chain_initialized','1')"
            )
            self.conn.commit()
            return
        # Upgrade a genuinely legacy ledger exactly once. Never silently
        # re-chain partially hashed rows, because that could hide tampering.
        if any(row["prev_hash"] or row["record_hash"] for row in rows):
            self._integrity_error = "partial hash-chain migration; manual review required"
            return
        previous = self.GENESIS
        for row in rows:
            fields = self._row_fields(row)
            digest = self._record_hash(fields)
            self.conn.execute(
                "UPDATE ledger SET prev_hash=?, record_hash=? WHERE id=?",
                (previous, digest, row["id"]),
            )
            previous = digest
        self.conn.execute(
            "INSERT INTO ledger_meta(key,value) VALUES('hash_chain_initialized','1')"
        )
        self.conn.commit()

    def add(self, event: dict) -> int:
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                ok, error = self._verify_rows()
                if not ok:
                    self._integrity_error = error
                    raise RuntimeError(f"audit ledger integrity check failed: {error}")
                previous_row = self.conn.execute(
                    "SELECT id, record_hash FROM ledger ORDER BY id DESC LIMIT 1"
                ).fetchone()
                next_id = (int(previous_row["id"]) + 1) if previous_row else 1
                previous_hash = previous_row["record_hash"] if previous_row else self.GENESIS
                fields = {
                    "id": next_id,
                    "fingerprint": str(event.get("fingerprint", "unknown"))[:64],
                    "threatType": str(event.get("threat_type", "ransomware")),
                    "timestamp": int(time.time()),
                    "pid": int(event.get("pid", 0) or 0),
                    "entropy": int(float(event.get("entropy", 0) or 0) * 100),
                    "processName": str(event.get("process", "unknown"))[:100],
                    "filePath": str(event.get("file_path", ""))[:200],
                    "actionTaken": str(event.get("action", "0")),
                    "status": str(event.get("status", "unknown")),
                }
                digest = self._record_hash(fields)
                self.conn.execute(
                    "INSERT INTO ledger "
                    "(id,fingerprint,threatType,timestamp,pid,entropy,processName,filePath,actionTaken,status,prev_hash,record_hash) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (*[fields[name] for name in self.FIELDS], previous_hash, digest),
                )
                self.conn.commit()
                self._integrity_error = None
                return next_id
            except Exception:
                self.conn.rollback()
                raise

    def count(self) -> int:
        with self._lock:
            return int(self.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0])

    def verify_chain(self) -> bool:
        with self._lock:
            ok, error = self._verify_rows()
            self._integrity_error = error
            return ok

    def integrity_status(self) -> dict:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM ledger ORDER BY id ASC").fetchall()
            ok, error = self._verify_rows(rows)
            head = rows[-1]["record_hash"] if rows else self.GENESIS
            self._integrity_error = error
            return {"verified": ok, "records": len(rows), "head": head,
                    "error": error, "mode": "local_sqlite_hash_chain",
                    "tamper_evident": True, "externally_anchored": False}

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def all(self) -> list:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM ledger ORDER BY id ASC"
            ).fetchall()
        return [
            {
                "id": row["id"], "fingerprint": row["fingerprint"],
                "threatType": row["threatType"], "timestamp": row["timestamp"],
                "pid": row["pid"], "entropy": (row["entropy"] or 0) / 100,
                "processName": row["processName"], "filePath": row["filePath"],
                "actionTaken": row["actionTaken"], "status": row["status"],
                "prev_hash": row["prev_hash"], "record_hash": row["record_hash"],
            }
            for row in rows
        ]


class BlockchainConnector:
    """
    Connects Python backend to Ganache + Solidity smart contract,
    with a transparent local-ledger fallback.

    Usage:
        bc = BlockchainConnector()
        bc.log_event({...})           # non-blocking
        events = bc.get_all_events()   # blocking read
    """

    def __init__(self):
        self.w3            = None
        self.contract      = None
        self.account       = None
        self.abi           = None
        self.last_connect  = 0
        self.connect_retry = 30   # seconds between reconnect attempts
        self.mode          = "none"   # 'ganache' | 'fallback' | 'none'
        self.fallback      = None
        self._write_queue   = Queue()
        self._worker       = None
        self._connect()
        self._worker = threading.Thread(
            target=self._write_worker,
            name="BlockchainWriter",
            daemon=True,
        )
        self._worker.start()

    # ═════════════════════════════════════════════════
    # CONNECTION MANAGEMENT
    # ═════════════════════════════════════════════════

    def _connect(self):
        """Establish connection to Ganache; fall back to local ledger."""
        if self._try_ganache():
            return

        if config.BLOCKCHAIN_FALLBACK:
            try:
                ledger_path = os.path.join(
                    config.BLOCKCHAIN_DIR, "ledger.db"
                )
                self.fallback = LocalLedger(ledger_path)
                self.mode = "fallback"
                print("[BLOCKCHAIN] Ganache unreachable — "
                      "using LOCAL LEDGER fallback ✅")
                log.info("Ganache unreachable; using local ledger fallback")
                return
            except Exception as e:
                print(f"[BLOCKCHAIN] ❌ Fallback ledger failed: {e}")

        self.mode = "none"
        print("[BLOCKCHAIN] ❌ No blockchain connection "
              "(Ganache offline, fallback disabled)")
        log.error("No blockchain connection available")

    def _try_ganache(self) -> bool:
        """Attempt to connect to Ganache and load the contract."""
        try:
            from web3 import Web3
            self.w3 = Web3(Web3.HTTPProvider(config.GANACHE_URL))

            if self.w3.is_connected():
                print("[BLOCKCHAIN] Connected to Ganache ✅")
                log.info("Connected to Ganache")
                if self._load_contract():
                    self.mode = "ganache"
                    self.last_connect = time.time()
                    return True
        except Exception as e:
            print(f"[BLOCKCHAIN] ❌ Ganache not reachable: {e}")
            log.error(f"Ganache not reachable: {e}")
        return False

    def _reconnect_if_needed(self):
        """Try to reconnect if we lost connection (Ganache mode only)."""
        if self.mode == "ganache":
            return True

        # Rate-limit reconnect attempts
        if time.time() - self.last_connect < self.connect_retry:
            return False

        self.last_connect = time.time()
        if self._try_ganache():
            return True

        # Re-establish fallback if it dropped
        if config.BLOCKCHAIN_FALLBACK and self.fallback is None:
            try:
                ledger_path = os.path.join(
                    config.BLOCKCHAIN_DIR, "ledger.db"
                )
                self.fallback = LocalLedger(ledger_path)
                self.mode = "fallback"
                return True
            except Exception:
                pass
        return self.mode != "none"

    def _load_contract(self):
        """Load the ThreatLogger contract using ABI file."""
        abi_path = os.path.join(
            config.BASE_DIR, "blockchain", "contract_abi.json"
        )

        if not os.path.exists(abi_path):
            print(f"[BLOCKCHAIN] ❌ No ABI at: {abi_path}")
            log.error(f"ABI file missing: {abi_path}")
            return False

        try:
            with open(abi_path) as f:
                self.abi = json.load(f)

            self.contract = self.w3.eth.contract(
                address=config.CONTRACT_ADDRESS,
                abi=self.abi
            )

            accounts = self.w3.eth.accounts
            if not accounts:
                print("[BLOCKCHAIN] ❌ No accounts in Ganache")
                log.error("No accounts available")
                return False

            configured = (config.WALLET_ADDRESS or "").strip()
            if configured:
                checksum = self.w3.to_checksum_address(configured)
                if checksum not in accounts:
                    print("[BLOCKCHAIN] ❌ ENTROPY_WALLET_ADDRESS is not a Ganache account")
                    return False
                self.account = checksum
            else:
                self.account = accounts[config.ACCOUNT_INDEX]

            print(f"[BLOCKCHAIN] Contract loaded ✅")
            print(f"             Address : {config.CONTRACT_ADDRESS}")
            print(f"             Account : {self.account}")
            log.info(f"Contract loaded at {config.CONTRACT_ADDRESS}")
            return True

        except Exception as e:
            print(f"[BLOCKCHAIN] ❌ Contract load failed: {e}")
            log.error(f"Contract load failed: {e}")
            return False

    # ═════════════════════════════════════════════════
    # WRITE — LOG EVENT
    # ═════════════════════════════════════════════════

    def log_event(self, event: dict):
        """Queue an event for serialized, reliable background writing.

        A single writer prevents Ganache nonce collisions when many files are
        detected at once. The queue can be drained with :meth:`flush` during
        an orderly shutdown.
        """
        self._write_queue.put(dict(event))

    def _write_worker(self):
        while True:
            event = self._write_queue.get()
            try:
                if event is None:
                    return
                self._log_event_dispatch(event)
            except Exception as exc:
                log.error("Blockchain writer failed: %s", exc)
            finally:
                self._write_queue.task_done()

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait for queued writes to finish during graceful shutdown."""
        deadline = time.time() + max(0.0, timeout)
        while self._write_queue.unfinished_tasks:
            if time.time() >= deadline:
                log.warning(
                    "Blockchain writer still has %d pending event(s)",
                    self._write_queue.unfinished_tasks,
                )
                return False
            time.sleep(0.01)
        return True

    def close(self, timeout: float = 10.0):
        """Drain pending writes and stop the writer thread."""
        drained = self.flush(timeout)
        if self._worker and self._worker.is_alive():
            self._write_queue.put(None)
            self._worker.join(timeout=max(0.0, timeout))
        if self.fallback is not None:
            try:
                self.fallback.close()
            except Exception:
                pass
        return drained

    def _log_event_dispatch(self, event: dict):
        if self.mode == "ganache":
            self._log_event_sync(event)
        elif self.mode == "fallback":
            try:
                self.fallback.add(event)
                print(f"  ✅ [LEDGER] Event recorded "
                      f"| fp={str(event.get('fingerprint',''))[:12]}…")
            except Exception as e:
                print(f"  ❌ [LEDGER] Write failed: {e}")
                log.error(f"Ledger write failed: {e}")
        else:
            if not self._reconnect_if_needed():
                print("  ❌ [BLOCKCHAIN] Not connected — skipping log")
                return
            self._log_event_dispatch(event)

    def _log_event_sync(self, event: dict):
        """Actual blockchain write — runs in background (Ganache mode)."""

        if not self.contract:
            if not self._reconnect_if_needed():
                print("  ❌ [BLOCKCHAIN] Not connected — skipping log")
                return

        if not self.contract:
            print("  ❌ [BLOCKCHAIN] Contract not loaded — skipping log")
            return

        try:
            tx_hash = self.contract.functions.logThreat(
                str(event.get("fingerprint", "unknown"))[:64],
                str(event.get("threat_type", "ransomware")),
                int(event.get("pid",         0)),
                int(event.get("entropy",     0) * 100),
                str(event.get("process",     "unknown")),
                str(event.get("file_path",   ""))[:100],
                str(event.get("action",      "0")),
                str(event.get("status",      "unknown"))
            ).transact({
                "from" : self.account,
                "gas"  : 500000
            })

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            print(f"  ✅ [BLOCKCHAIN] TX Block #{receipt.blockNumber} "
                  f"| Gas: {receipt.gasUsed}")
            log.info(f"TX confirmed: block {receipt.blockNumber}")

        except ValueError as e:
            print(f"  ❌ [BLOCKCHAIN] Rejected: {e}")
            log.error(f"TX rejected: {e}")

        except ConnectionError as e:
            print(f"  ❌ [BLOCKCHAIN] Connection lost: {e}")
            log.error(f"Connection lost: {e}")
            self.contract = None   # force reconnect on next call

        except Exception as e:
            print(f"  ❌ [BLOCKCHAIN] Failed: {e}")
            log.error(f"Log failed: {e}")

    # ═════════════════════════════════════════════════
    # READ — GET EVENTS
    # ═════════════════════════════════════════════════

    def get_all_events(self):
        """Read all events from the active ledger / contract."""
        if self.mode == "fallback":
            try:
                return self.fallback.all()
            except Exception as e:
                log.error(f"Ledger read failed: {e}")
                return []

        if self.mode != "ganache":
            self._reconnect_if_needed()
            if self.mode != "ganache":
                return []

        try:
            count = self.contract.functions.getEventCount().call()
            events = []

            for i in range(count):
                raw = self.contract.functions.getEvent(i).call()
                events.append({
                    "id"          : raw[0],
                    "fingerprint" : raw[1],
                    "threatType"  : raw[2],
                    "timestamp"   : raw[3],
                    "pid"         : raw[4],
                    "entropy"     : raw[5] / 100,
                    "processName" : raw[6],
                    "filePath"    : raw[7],
                    "actionTaken" : raw[8],
                    "status"      : raw[9]
                })

            return events

        except Exception as e:
            print(f"[BLOCKCHAIN] ❌ Read failed: {e}")
            log.error(f"Read failed: {e}")
            return []

    def get_event_count(self):
        """Get total number of events in ledger."""
        if self.mode == "fallback":
            try:
                return self.fallback.count()
            except Exception:
                return 0

        if self.mode != "ganache":
            self._reconnect_if_needed()
            if self.mode != "ganache":
                return 0

        try:
            return self.contract.functions.getEventCount().call()
        except Exception as e:
            log.debug(f"Count failed: {e}")
            return 0

    # ═════════════════════════════════════════════════
    # STATUS
    # ═════════════════════════════════════════════════

    def verify_chain(self):
        """Return True only for an actual Ganache connection."""
        if self.mode != "ganache":
            return False
        try:
            return self.w3 is not None and self.w3.is_connected()
        except Exception:
            return False

    def get_status(self):
        """Get truthful ledger and connection status for diagnostics."""
        ledger_integrity = (self.fallback.integrity_status()
                            if self.mode == "fallback" and self.fallback
                            else None)
        return {
            "mode"           : self.mode,
            "connected"      : self.verify_chain(),
            "is_blockchain"  : self.mode == "ganache",
            "is_tamper_evident": bool(ledger_integrity and ledger_integrity["verified"]),
            "ledger_integrity": ledger_integrity,
            "contract_loaded": self.contract is not None,
            "account"        : self.account,
            "contract_addr"  : config.CONTRACT_ADDRESS if self.contract else None,
            "network_url"    : config.GANACHE_URL,
        }