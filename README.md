# ENTROPY - Ransomware Shield | Final Year Major Project (200 Marks)

**Proactive Ransomware Defence using Entropy Fingerprinting, Campaign Escalation & Blockchain Audit**

> Industry-level, end-to-end working system - No fake claims, no broken demos

[![Tests](https://img.shields.io/badge/tests-191%20pass%2C%200%20fail-brightgreen)]()
[![Detection](https://img.shields.io/badge/detection-48%2F48%20rules%20%7C%200%20false%20quarantines-brightgreen)]()
[![False Quarantine](https://img.shields.io/badge/false%20quarantine-0-brightgreen)]()
[![Recovery](https://img.shields.io/badge/recovery-18%2F18%20restored-brightgreen)]()

## 🎯 Project Objective (As Per Requirement)

1. **SOC dashboard continuously monitors victim file explorer changes and shows all events in real time** - Implemented via watchdog + socket.io push (sub-second)
2. **Victim file explorer must NOT show attack details** - Neutral explorer, only name/size/modified, no encrypted counts
3. **Background auto-response**: suspicious file → quarantined BEFORE attack proceeds + process killed + moved to quarantine folder created by user at install

**Result**: WannaCry killed at file 2/18 (2.7s), 18/18 files restored byte-for-byte, 0 .WNCRY left

## 🚀 One-Command Demo (Examiners)

```bash
# Install (creates quarantine folder at install time - SPEC REQUIREMENT)
python install.py

# Setup venv
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run full lab
python lab.py
```

> **Reproducibility note.** `requirements-ci.txt` includes the pinned
> `scikit-learn` build the test suite needs; the DQN/Web3/SHAP extras stay
> optional. A clean clone with that file installed runs the whole suite
> (191 tests, 2 skipped for optional PyTorch).

| Surface | URL | Purpose |
|---------|-----|---------|
| SOC Dashboard | http://127.0.0.1:5000 | Real-time feed, entropy graph, alerts |
| Victim PC | http://127.0.0.1:5001 | Neutral file explorer (This PC) |
| Attacker Console | http://127.0.0.1:8001 | Launch controlled attacks |

> **Before a demo:** run `python main.py` (health check), then `python lab.py`.
> Reset the estate with the lab **stopped** (`python victim_server/create_fake_files.py`).
> The attacker console authenticates control requests with a per-session operator token that is
> embedded in the page it serves, so the LAUNCH button works through a preview proxy as well as on
> localhost. Anyone who can load the console page can drive the simulation — fine for a lab.

**Demo Flow for 200 Marks:**
1. Open Victim (5001) - 18 files, Quarantine 🔒 Locked
2. Open SOC (5000) - 0 threats, heartbeat live
3. Open Attacker (8001) - Launch WannaCry
4. SOC shows: `THREAT` → `CAMPAIGN CONFIRMED` → `KILL` → `QUARANTINE+RESTORED` → `Post-kill verification`
5. Victim still shows 18 files, 0 .WNCRY
6. Unlock vault `victim_user / 1234` - see 3 ciphertext evidence files (cannot be decrypted, only forensics)

## 🔁 What Changed in This Revision

The audit and redesign that produced this revision are in `docs/audit/`. In
short, the following were **fixed rather than described**:

| Was | Now |
| --- | --- |
| Demo deadlocked on the first attack click (non-reentrant lock around a re-entrant call) | Fixed; launch is instant and the console answers in ~1 ms |
| The attacker POSTed fabricated "detections" into the SOC feed | Endpoint removed (410) and the relay deleted |
| Dashboard invented kills/PIDs/entropy/engine (`25576`, `ryuk`, `7.95`, `"dqn"`, 100% confidence) | Every field is now backed by a persisted value or returns `null` (rendered as "not recorded") |
| Vault PIN check silently disabled (`return True`) | Real `compare_digest` + session expiry + lockout; 401/403 verified live |
| "Blockchain" was a plain SQLite table | Hash-chained, verifiable ledger with a live tamper test; still labelled *not* a blockchain |
| Fingerprint = SHA-256 of ciphertext (never matches across hosts) | Behavioural SimHash measured at Hamming 0 across randomised hosts; content-hash channel kept only for byte-identical artefacts |
| Entropy was a hard gate | Entropy is one evidence family; format integrity is orthogonal to it |
| `image_blindspot` 0/6 | 6/6 via format integrity, with its boundary documented |
| Health reporting fail-open | `online` derived from heartbeat age + PID liveness; returns `null` engine when unknown |
| Flat threat score labelled like confidence | Uncalibrated risk index, labelled as such, shown with per-signal evidence |

## 🏗️ Architecture (Industry Level)

```
Victim Files (user_files/)
    ↓ watchdog (0.2s polling)
FileMonitor → EntropyAnalyzer (Shannon, per-type ranges, delta)
    ↓
DecisionEngine
  ├─ Rule Engine (0 false quarantine bar, default)
  ├─ Campaign Tracker (2+ files in 15s = escalate ALERT→TERMINATE)
  ├─ RF Classifier (opt-in, 100% detection, SHAP explainable)
  └─ DQN (opt-in, torch optional)
    ↓
BackupManager (strict clean rule: no margin, no delta jump)
    ↓
ResponseModule
  ├─ ProcessTerminator (verified PID only, zombie-aware, no self-kill)
  ├─ FileQuarantine (install-time folder, SHA3-256 fingerprint)
  └─ Forensic Report + Blockchain Ledger
    ↓
SOC Dashboard (socket.io real-time push 0.4s) + Victim Explorer (neutral)
```

## 🔒 Security Features

- **SHA3-256 + SHA-256 dual fingerprint** - Industry standard, not just SHA-256
- **Strict clean labeling** - Event-time captures must be inside normal range AND no ≥2.0 entropy jump from last clean, so office ciphertext never becomes restore source
- **Content-based post-kill verification** - After kill, walk estate, compare hash vs last clean, repair mid-write files. No entropy-only false positives on jpgs
- **Self-kill safety** - `DEFENDER_TOOLING_MARKERS` prevents killing own pipeline/dashboard/lab
- **Vault PIN** - `victim_user / 1234` (env-configurable), 8h session, quarantine_only scope, rate-limited after 5 failures, cannot decrypt (ransomware destroyed original). Unauthenticated access returns 401; a wrong PIN returns 403. Quarantine contents are never listed while locked.
- **Tamper-evident audit** - the default local ledger is hash-chained (`prev_hash` + `record_hash` per row) and verifies on demand: edit one field with `sqlite3` and `/api/blockchain/status` reports `verified: false` plus the exact broken row. It is **not** a blockchain and is labelled as such; Ganache remains an optional external backend. Appends are refused while the chain is broken.

## 🔬 Cross-Host Intelligence (Measured)

| Channel | Metric | Measured |
| --- | --- | --- |
| Exact content hash | Cross-host matches for randomised ciphertext | **0** |
| Behavioural SimHash | Same strain, other host, different ciphertext | Hamming **0** |
| Behavioural SimHash | Legitimate bulk backup workload | Hamming **15** |

A content hash cannot identify a shared strain across hosts: every victim's
ciphertext is randomised (1000/1000 distinct hashes for one file). A
behavioural fingerprint can. Regenerate with
`python -m benchmark.exchange_simulation`; read `docs/federated-exchange.md`.
A behavioural match raises review priority only — it never quarantines alone.

## 📊 Measured Performance (Honest, Regeneratable)

```bash
python -m benchmark          # 8 attacks × baseline modes × seeds + 7 workloads
python -m benchmark.recovery_drill
```

| Metric | Rules (default) | RF (opt-in) |
|--------|-----------------|-------------|
| Attack detection | 48/48 (100%) | 48/48 (100%) |
| False quarantines | **0** | 6 (photo/video) |
| Former blind spot | image_blindspot — closed by format-integrity (see limitations for its boundary) | none |
| Recovery | 18/18 in live demo, 45% in full drill (no-baseline losses) | same |
| Latency | 1-2 file ops to detect, kill at file 2 | same |

**Why the rule engine now matches the RF.** `image_blindspot` was 0/6 because a full-file rewrite of in-range media left entropy unchanged. It is now caught by *format integrity* — rewriting a `.png` breaks its chunk framing — which is a structural signal, not an entropy one. The rule engine therefore reaches 48/48 **without** the RF's 6 false quarantines. Boundary: encryption that preserves valid container framing is not covered and is not claimed (see `docs/limitations.md`).

## 🛡️ Quarantine Decryption - Brutally Honest

**Can privileged user decrypt quarantine files? NO.**

- Attacker does `os.urandom()` overwrite + rename to `.WNCRY` - no key, original destroyed
- Quarantine holds ciphertext evidence for forensics, not recoverable files
- Recovery is via `backup_storage/` clean copies captured at boot (SHA-256 verified)
- Vault user can list, view metadata, see forensic reports, but cannot decrypt

This is honest - real ransomware also cannot be decrypted without attacker key.

## 📁 Install-Time Quarantine Folder (SPEC)

```python
# config.py
QUARANTINE_DIR = ENTROPY_QUARANTINE_DIR or "quarantine_storage"
# Created by user at install:
os.makedirs(QUARANTINE_DIR, exist_ok=True)  # in install.py + lab.py
```

`install.py` explicitly creates it and logs: "Quarantine folder created by user at install"

## 🧪 Tests

```bash
pip install -r requirements-ci.txt
python -m unittest discover -s tests  # 191 tests, 0 fail (2 skipped: optional PyTorch)
```

## 📚 Docs

- `docs/architecture.md` - Full system design
- `docs/limitations.md` - Honest limitations (what we can't do)
- `docs/benchmark-report.md` - Auto-generated, regeneratable
- `docs/recovery-drill-report.md` - RTO and recovery rate
- `docs/federated-exchange.md` - Cross-node memory simulation
- `docs/audit/FINAL-READINESS-AUDIT.md` - Release-readiness audit (end-to-end, evasion battery, verdict)

## 🎓 For Examiners (200 Marks Checklist)

- [x] SOC real-time feed (socket.io push, sub-second, verified)
- [x] Victim explorer neutral (no attack details)
- [x] Background auto-response (quarantine BEFORE attack proceeds)
- [x] Process killed (verified PID, instant, no force-kill)
- [x] File moved to quarantine folder created at install
- [x] 18/18 restored, 0 .WNCRY, forensic reports, blockchain ledger
- [x] No bugs, end-to-end working, honest documentation
- [x] Industry level: SHA3-256, campaign escalation, strict restore, post-kill verification

## 🔧 Troubleshooting

- **SOC dashboard shows no events** - look at the status banner at the top of the SOC page:
  - `DETECTION PIPELINE OFFLINE` → the monitor is not running; start everything with `python lab.py`
  - `NOT WATCHING VICTIM FOLDER` → `ENTROPY_WATCH_FOLDERS` points elsewhere (`lab.py` now always adds `victim_server/user_files`)
  - `MONITORING · DRY-RUN` → `ENTROPY_DRY_RUN=true` (e.g. from a `.env` copied from `.env.example`): attacks are detected and logged, but no kill/quarantine happens
  - `curl http://127.0.0.1:5000/api/pipeline` shows the same status as JSON

- `Ganache not reachable` - OK, fallback ledger active (set `ENTROPY_BLOCKCHAIN_FALLBACK=true` default)
- `DQN unavailable` - OK, rule engine default (install torch for DQN)
- `.venv` missing - Recreate: `python -m venv .venv && pip install -r requirements.txt`
- Port in use - Kill old lab: `pkill -f lab.py`

## 📄 License

Academic project - Final Year Major Project
