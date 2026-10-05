"""Local SQLite registry for fuzzy behavioural fingerprints.

In this repository, the registry is a shared local store for controlled
multi-node simulation; it does not replicate over a network. Signatures only
become corroborated after distinct node IDs report a quarantined incident.
Fuzzy matches are advisory and cannot by themselves trigger containment.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

import config
from fingerprint.behavioral import hamming_distance
from blockchain.fingerprint_exchange import default_node_id


class BehavioralIntelExchange:
    def __init__(self, db_path: str | None = None, node_id: str | None = None,
                 max_distance: int = 6, confirm_sources: int | None = None):
        self.db_path = db_path or config.THREAT_EXCHANGE_DB
        self.node_id = node_id or default_node_id()
        self.max_distance = max(0, min(16, int(max_distance)))
        self.confirm_sources = int(confirm_sources or config.EXCHANGE_CONFIRM_THRESHOLD)
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS behavioral_fingerprints (
            fingerprint TEXT PRIMARY KEY,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            observations INTEGER NOT NULL DEFAULT 1,
            sources TEXT NOT NULL DEFAULT '[]',
            evidence TEXT NOT NULL DEFAULT '',
            event_count INTEGER NOT NULL DEFAULT 0
        )""")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_behavior_last_seen ON behavioral_fingerprints(last_seen)")
        self._conn.commit()

    def lookup(self, fingerprint: str) -> dict:
        fingerprint = (fingerprint or "").strip().lower()
        if len(fingerprint) != 16:
            return {"matched": False, "confirmed": False, "distance": None,
                    "sources": [], "fingerprint": fingerprint}
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM behavioral_fingerprints ORDER BY last_seen DESC LIMIT 5000"
            ).fetchall()
        candidates = []
        for row in rows:
            distance = hamming_distance(fingerprint, row["fingerprint"])
            if distance <= self.max_distance:
                try:
                    sources = json.loads(row["sources"] or "[]")
                except ValueError:
                    sources = []
                candidates.append((distance, row, sources))
        if not candidates:
            return {"matched": False, "confirmed": False, "distance": None,
                    "sources": [], "fingerprint": fingerprint}

        # Corroboration accumulates across the whole near-neighbour CLUSTER,
        # not just the single closest signature. Two hosts observing the same
        # behaviour rarely produce bit-identical SimHashes, so counting only
        # exact matches would under-count independent corroboration. Distinct
        # node IDs are still required, so one noisy node cannot confirm alone.
        cluster_sources: list[str] = []
        for _distance, _row, candidate_sources in candidates:
            for source in candidate_sources:
                if source not in cluster_sources:
                    cluster_sources.append(source)
        distance, row, _sources = min(
            candidates, key=lambda item: (item[0], -item[1]["last_seen"])
        )
        return {
            "matched": True,
            "confirmed": len(cluster_sources) >= self.confirm_sources,
            "distance": distance,
            "sources": cluster_sources,
            "cluster_size": len(candidates),
            "observations": sum(int(item[1]["observations"]) for item in candidates),
            "evidence": row["evidence"],
            "fingerprint": row["fingerprint"],
        }

    def register(self, fingerprint: str, *, evidence: str = "",
                 event_count: int = 0, now: float | None = None) -> dict:
        fingerprint = (fingerprint or "").strip().lower()
        if len(fingerprint) != 16 or any(c not in "0123456789abcdef" for c in fingerprint):
            raise ValueError("behavioral fingerprint must be 16 lowercase hex characters")
        now = time.time() if now is None else float(now)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM behavioral_fingerprints WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO behavioral_fingerprints "
                    "(fingerprint, first_seen, last_seen, observations, sources, evidence, event_count) "
                    "VALUES (?, ?, ?, 1, ?, ?, ?)",
                    (fingerprint, now, now, json.dumps([self.node_id]),
                     str(evidence or "")[:500], int(event_count or 0)),
                )
            else:
                try:
                    sources = json.loads(row["sources"] or "[]")
                except ValueError:
                    sources = []
                if self.node_id not in sources:
                    sources.append(self.node_id)
                self._conn.execute(
                    "UPDATE behavioral_fingerprints SET last_seen=?, observations=observations+1, "
                    "sources=?, evidence=?, event_count=? WHERE fingerprint=?",
                    (now, json.dumps(sources[-100:]), str(evidence or row["evidence"])[:500],
                     max(int(event_count or 0), int(row["event_count"] or 0)), fingerprint),
                )
            self._conn.commit()
        return self.lookup(fingerprint)

    def stats(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS fingerprints, COALESCE(SUM(observations),0) AS observations "
                "FROM behavioral_fingerprints"
            ).fetchone()
            confirmed = 0
            for item in self._conn.execute("SELECT sources FROM behavioral_fingerprints"):
                try:
                    confirmed += len(set(json.loads(item[0] or "[]"))) >= self.confirm_sources
                except ValueError:
                    continue
        return {"fingerprints": int(row["fingerprints"]),
                "observations": int(row["observations"]),
                "corroborated_fingerprints": int(confirmed),
                "mode": "local_shared_registry"}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
