# FINAL RELEASE-READINESS AUDIT

**Date:** 2026-10-04 · **Branch:** `arena/01a10629-entropyy` · **Base commit:** `5fc176a` + audit fixes below
**Environment:** Linux sandbox, Python 3.11.2, `.venv` from `requirements-ci.txt` (no torch / web3 / eventlet — all three degrade to documented fallbacks)
**Method:** every claim below is backed by an executed command. Evidence artifacts: `docs/audit/evidence/*.json`.

> **Verdict up front: 🟡 DEMO-READY WITH KNOWN LIMITATIONS** — the complete critical demo path was
> executed end-to-end three times and works; three real defects were found and fixed during this
> audit; two detector bypasses and several research gaps remain open and are listed honestly.

---

## 0. What changed during this audit

Three defects were found by running the system, not by reading it. All three are fixed and re-verified.

| # | Severity | Defect found | Evidence | Fix | Re-verified |
|---|---|---|---|---|---|
| 1 | **CRITICAL** | `POST /api/launch` returned **403** to a real browser through the preview proxy — the demo's attack trigger was dead. Seen in the live log: `[attacker] "POST /api/launch HTTP/1.1" 403` | Control gate accepted only loopback or a bearer token; the browser is neither | 3-way gate: operator token **or** loopback **or** same-site request (Origin/Referer host == Host / X-Forwarded-Host); per-session token embedded in the console page | 6/6 matrix on real non-loopback sockets, incl. preview-shaped request → 200; 16 unit tests |
| 2 | **HIGH** | **174 of 200 legitimate files were ALERTED** by a bulk-copy burst (false-positive flood) | `make_decision()` alerted on write velocity alone; risk escalation needed only 2 velocity families | Velocity removed as an alert rule; risk-driven escalation requires an evidence family attributable to *this* file's content | 200 clean files → **200 events, 0 alerts, 0 quarantines** |
| 3 | **MEDIUM** | A **benign file created 8 s after an incident** was alerted at risk 0.90 (inherited campaign evidence) | `repeated_format_anomaly` + `multi_file_scope` + behavioural match are computed over *other* recent files | History-derived families excluded from the escalation gate (still contribute to the risk index) | Post-incident probe now `IGNORED` (risk still shown as 0.89) |

A pre-existing test (`tests/test_control_security.py`) pinned the old token behaviour; the first version of fix #1 broke it, which the suite caught. Final implementation satisfies both the old and new security tests.

**Test count: 174 → 191 passing, 0 failing, 2 skipped.**

---

## 1. End-to-end functional verification

Real events, real processes, real HTTP. Each row was exercised in the live run (`docs/audit/evidence/e2e_result.json`).

| # | Component | File / class | Supposed to | Works? | How tested | Result |
|---|---|---|---|---|---|---|
| 1 | Protection agent | `monitoring/watchdog_monitor.py` + `monitoring/pipeline_runner.py::main` | Watch folders recursively, emit real file events | ✅ | Created/edited/copied/renamed/deleted/zipped files in the watched folder | 27 events from 8 real operation groups; 200-file burst produced 200 events |
| 2 | Folder/file monitoring | `PollingMonitor` (1 s poll), protected-store watch on `backup_storage/`, `quarantine_storage/` | Observe create/modify/rename/delete | ✅ | All five event types exercised | `CREATED/MODIFIED/RENAMED/DELETED` all persisted |
| 3 | Feature extraction — entropy | `entropy/entropy_calculator.py` | Shannon entropy, 3-zone sampling, delta vs history | ✅ | Real attack payload measured | Attack rows: `entropy 7.78–7.89`, `delta 0.59–2.85`, benign rows `3.39–3.95` |
| 4 | Feature extraction — structure | `detection/structure.py` | Non-executing format integrity (PNG/PDF/ZIP/Office/MP4) | ✅ | Attacker rewrote `.xlsx` and `.pdf` in place | `{"anomaly": true, "evidence": "missing ZIP central directory"}` / `"missing PDF header or EOF marker"` |
| 5 | Feature extraction — behavioural | `fingerprint/behavioral.py` | 64-bit SimHash over the operation sequence | ✅ | Campaign events fingerprinted | Identical fingerprint `3651fae4bd8a67b0` across 4 campaign events |
| 6 | Risk engine | `decision/risk_engine.py::RiskEngine` | Multi-family evidence index, labelled uncalibrated | ✅ | Per-event assessment | `risk 0.82 → 0.93 → 0.987`, evidence list populated, `risk_method: uncalibrated_noisy_or_evidence_index` |
| 7 | Decision engine | `pipeline_runner.py::DecisionEngine.decide` | Separate detection / decision / response | ✅ | Benign vs attack vs post-incident | Benign `IGNORE`; campaign `TERMINATE+QUARANTINE`; post-incident benign `IGNORE` |
| 8 | Detection | `make_decision()` + hard-confirmation signals | Decide suspicious vs not | ✅ | 48-scenario battery + live attack | see §3 |
| 9 | Response — termination | `response/response_module.py::ProcessTerminator` | Kill the verified attacker process, never a system process | ✅ | Live attack, PID 4483/4620 | `[TERMINATE] SUCCESS: PID … terminated`; kill at 1.0–1.4 s; one attempt correctly **refused** when identity could not be re-verified |
| 10 | Response — quarantine | `FileQuarantine.quarantine` | Move the file to quarantine with metadata | ✅ | Live attack | 3 files + 3 `.meta.json` in `quarantine_storage/` |
| 11 | Recovery | `response/backup_manager.py` | Restore a known-good copy captured pre-attack | ✅ | Live attack | `restore_result = RESTORED` on all 3 rows; estate back to 0 encrypted |
| 12 | Incident creation | `storage/database.py` (schema v5) | Persist the full incident record | ✅ | DB inspection | 4 attack rows with entropy, risk, evidence, structure, fingerprint, human explanation |
| 13 | Audit / ledger | `blockchain/connector.py::LocalLedger` | Hash-chained tamper-evident record | ✅ | Live tamper drill (§5.8) | `verify_chain() True → False → True`; 38 records |
| 14 | SOC dashboard | `app.py` + Socket.IO | Real numbers, live push | ✅ | `/api/stats`, `/api/pipeline`, `/api/threat-level` | `terminated 2, quarantined 3, recovery 3, max_risk 0.987`; `/api/telemetry` correctly returns **410** |
| 15 | Continuous monitoring | monitor loop | Keep watching after containment | ✅ | Probe file 8 s after the incident | Probe seen, `pipeline_online: true`, processed as `IGNORED` |

**Not verified here (honest):** process-tree/ancestry monitoring does not exist (objective #6 is still partial); the defence-tamper cmdline scan looks for Windows tooling strings and was not triggered on Linux; real Windows execution was not possible in this sandbox.

---

## 2. Realistic ransomware simulation

Safe simulation only, inside `victim_server/user_files`, driven through the console's own token path.

Timeline of the final run (`e2e_result.json`):

| t | Event |
|---|---|
| 0.000 s | `POST /api/launch {"family":"wannacry"}` → **200 OK**, child PID started |
| 0.206 s | first incident row persisted (structure anomaly on the first rewritten file) |
| 0.206 s | first response action recorded (`ALERTED`, risk 0.92) |
| ~0.4–1.2 s | campaign confirmed (2 files with encrypted-data signatures); `TERMINATE+QUARANTINE` |
| **1.22 s** | attacker process **KILLED_BY_DEFENDER** (exit code 42, `defender_killed: true`) |
| +5 s | 3 files quarantined, all **RESTORED** from the pre-attack backup; estate `0 encrypted`, `OPERATIONAL` |

All twelve required checkpoints passed:

1. ✅ Detected · 2. ✅ Earliest stage (first/second file operation; 1 of 43 files touched = 2.3 %) · 3. ✅ Signals computed (entropy, delta, structure, burst, scope, writer context) · 4. ✅ Fingerprint generated (`3651fae4bd8a67b0`) · 5. ✅ Risk/decision produced (0.987, uncalibrated, with evidence list) · 6. ✅ Incident created · 7. ✅ Containment executed (process killed) · 8. ✅ Quarantine performed (3 files + metadata) · 9. ✅ Event recorded · 10. ✅ Audit ledger appended (hash-chained) · 11. ✅ SOC dashboard shows it · 12. ✅ Monitoring continued afterwards.

**Not fake:** the attacker engine really overwrites bytes (`bytes_encrypted: 2197`, `files_hit: 1`), the killed PID is real (`returncode 42`), quarantine files contain the real corrupted bytes, and the restore used a SHA-256-verified pre-attack copy. No event, alert or ledger row in this run was injected.

---

## 3. Legitimate-activity / false-positive test

Live benign workload (create, edit, copy, rename, delete, ZIP, 20-file bulk copy, reads) plus a separate 200-file burst:

| Run | Events | Alerted | Quarantined | Terminated |
|---|---|---|---|---|
| Live benign workload (final run) | 27 | 0 | 0 | 0 |
| Live 200-file bulk burst (final code) | 200 | **0** | 0 | 0 |
| Committed benchmark, 7 legitimate workloads × 3 runs | 21 runs | **0** | **0** | 0 |

Measured metrics (Rules engine, all evidence from this session):

| Metric | Value | Basis |
|---|---|---|
| True positives | 48 | benchmark attack runs (8 scenarios × 6) |
| False negatives | 0 | same |
| False positives | 0 | 21 benchmark workload runs + 227 live benign events |
| True negatives | 21 (+227 events) | same |
| **Precision** | **1.00** | 48/(48+0) |
| **Recall** | **1.00** | 48/(48+0) |
| **F1** | **1.00** | — |
| Detection latency | **206 ms** | launch → first persisted incident row |
| Containment latency | **1.0–1.4 s** | launch → `KILLED_BY_DEFENDER` (3 runs: 1.01 / 1.22 / 1.42 s) |
| Files damaged before containment | **1 of 43 (2.3 %)** | live run |
| Median ops to detect | 1–2 | benchmark report |

> **These numbers are honest, not universal.** They are measured on *synthetic fixtures* with a
> known-good baseline; the entropy ranges are still fitted to synthetic files. Precision/recall of
> 1.00 on this battery must never be presented as real-world accuracy — §5 and §4 say why.

---

## 4. Research-gap audit

### A. Fully implemented contributions
- Three-layer split: detection (`make_decision`) / decision (`RiskEngine`, uncalibrated index) / response (`ProcessTerminator` + `FileQuarantine` + `BackupManager`) — verified live.
- Behavioural SimHash over operation sequences with a *measured* contrast against content hashes: content hash 0/1 cross-host matches on randomised ciphertext; same strain on another host Hamming **0**; benign bulk backup Hamming **15**; match radius 6.
- Format-integrity signal that closes the former `image_blindspot` (0/6 → 6/6) without touching entropy thresholds.
- Velocity/scope evidence explicitly demoted from alert triggers (measured fix, §0).
- Hash-chained tamper-evident audit ledger with refusal to append to a broken chain.
- Recovery by pre-attack backup with SHA-256 verification and strict clean-labelling.

### B. Partially implemented
- **Process behaviour monitoring (objective #6):** verified-writer attribution, identity re-check before kill, defender-tooling exclusion — but no process tree, ancestry, I/O counters or creation auditing.
- **Unknown/modified ransomware (objective #9):** structure check closes the in-place-rewrite case; entropy-preserving/format-preserving encryption is still missed (§5.1).
- **Threat-intel sharing (objective #14):** implemented behaviourally with independent node IDs and a ≥2-node threshold — but it is one shared SQLite file with simulated node identities, not a network.
- **Immutable audit (objective #13):** tamper-**evident**, not tamper-**proof**; no external anchor.
- **Protecting unaffected files (objective #12):** post-hoc sweep and restore only; no canaries, no write blocking.
- **Distinguishing legit high-entropy work (objective #8):** clean on the battery, but calibrated on synthetic fixtures.
- **Latency/overhead measurement (objectives #19, §22 of the brief):** measured in this audit (206 ms / 1.0–1.4 s; 1.8 % idle CPU; 28 % CPU at 10 files/s; ~130 MB RSS) but not yet part of the committed benchmark output.

### C. Claimed but not implemented
- **Objective #21 — A/B/C baseline comparison (entropy-only vs hash+entropy vs behaviour-only vs proposed): NOT IMPLEMENTED.** The repository only compares engines *inside* one architecture (rules vs Random Forest). This is the single objective with no implementation, and it is not closable tonight without new code.
- **No real-malware corpus.** All detection numbers come from synthetic fixtures; `NapierOne` or equivalent is not integrated. The literature specifically flags this as the field's reproducibility gap — this project currently shares it.

### D. In the code but not scientifically justified
- `ai/dqn_model.py` (~711 lines) is dead weight in the default path: no weights in the repo, torch not installed, engine is never `dqn` by default. It is honestly labelled at runtime but should be deleted or moved to an appendix.
- `config.NORMAL_ENTROPY_RANGES` are hand-written, e.g. `.docx` 6.0–7.5, while real Office documents measure ≈6.69 and the repository's own fixture measures 7.15. The ranges are fitted to the fixtures, not to reality.
- `test_blockchain.py` (repo root) is a legacy Windows script (`sys.path.append(r"C:\Entropy")`, `C:\Users\...` paths) that cannot run here.
- The threshold values (`6.8`, `2.0`, `3.0/s`, match radius `6`) are chosen by construction, not fitted — the literature has no guideline for similarity-hash thresholds either.

### E. Important limitations (carried forward, unchanged)
Best-effort process attribution; per-type entropy ranges from synthetic data; backup version cap; recovery limited to files with a clean pre-attack version; local-only intelligence; ledger not anchored.

### F. Remaining research gaps
1. Entropy-preserving encryption is undetected (§5.1) — the same limit the base literature reports for entropy-sharing.
2. No baseline comparison (objective #21).
3. No real-file corpus → thresholds not externally validated.
4. No kernel-level or pre-emptive protection; detection is inherently post-event.
5. Behavioural similarity threshold is uncalibrated; no false-correlation study at scale.

### G. What is genuinely novel here (and what is not)
- **Not novel:** Shannon entropy on file writes (1990s–2000s), SimHash on opcode/sequence data (MHAS, PLOS ONE 2019), honeypots/canaries (Moore 2016), blockchain CTI logging (several 2024–2026 systems), I/O-pattern behavioural detection (ERW-Radar, NDSS 2025).
- **Honest contribution:** the *integration and its measurement* — a three-layer agent where an uncalibrated multi-family index is explicitly separated from the containment decision; a **measured** demonstration that content hashes are useless across hosts on randomised ciphertext while operation-sequence fingerprints still correlate; and an explicit, reproducible record of which attacks it misses. That is a defensible engineering contribution, not a new detection principle.

---

## 5. Security / attack-surface audit

Each weakness was tested with a real technique, as a separate child process (`docs/audit/evidence/bypass_result.json`).

| # | Weakness | Test performed | Result | Sev | Fix before tomorrow? |
|---|---|---|---|---|---|
| 1 | Entropy-only evasion | XOR-encode 10 files with a constant key (content destroyed, entropy unchanged, format not checkable) | ❌ **UNDETECTED** (10 files, max risk 0.53) | **High** | No — documented; demo must not claim it is caught |
| 1b | Same, low-and-slow | XOR 3 files, 8 s apart | ❌ **UNDETECTED** (max risk 0.44) | High | No — documented |
| 2 | Fast encryption burst | Random-overwrite 20 files | ✅ Detected, 20/20 flagged | — | — |
| 3 | Extension camouflage | Encrypt 10 files keeping `.txt` names | ✅ Detected 10/10 (structure + delta) | — | — |
| 4 | Low-and-slow high-entropy | 4 files, 6 s apart | ✅ Detected 4/4 | — | — |
| 5 | Monitoring blind spot | Encrypt 5 files outside the watched folders | ❌ Invisible (0 events) | **Medium** | No — inherent to scope; state it |
| 6 | Duplicate events / event loss | 200 files created at ~10/s | ✅ 200 events, 0 duplicates at the file level | — | — |
| 7 | Audit-integrity attack | `UPDATE ledger SET status='BENIGN'` on row 1 | ✅ `verify_chain()` True → **False** → True after restore | — | — |
| 8 | Unauthenticated control | Non-loopback `POST /api/stop` with no credentials | ✅ **403** (foreign Origin also 403) | — | — |
| 9 | Dashboard/API exposure | `/api/telemetry` injection, `/api/demo/trigger` | ✅ 410 and 409 respectively; no destructive unauthenticated route | — | — |
| 10 | Vault brute force | Unauthenticated `/api/quarantine`; wrong PIN | ✅ 401 / 403; 5 failures → 300 s lockout | — | — |
| 11 | Kill-safety failure | Campaigned process with unverifiable identity | ✅ Termination **refused**; quarantine proceeded | — | — |
| 12 | DB reset under a running agent | Deleted `entropy.db` while the pipeline ran | ⚠️ `Save failed: attempt to write a readonly database` — recovers only after restart | Low | No — but the reset procedure must stop the lab first |
| 13 | Session token exposure | Console page embeds the operator token | ⚠️ By design: **access to the console page == control of the simulation** | Low | Accepted for a lab; document it |

---

## 6. Code-quality audit

| Check | Result |
|---|---|
| Broken imports / syntax | ✅ `compileall` clean across 60+ modules; `python main.py` health check exits 0 |
| Test suite | ✅ 191 pass, 0 fail, 2 skipped |
| Hardcoded absolute paths | ⚠️ Only `test_blockchain.py` (legacy root script, `C:\Entropy`, `C:\Users\…`); none in the package |
| Hardcoded results / fake data | ✅ none found: telemetry endpoint returns 410, demo trigger 409, dashboard counters derived from the DB, `confidence` is `None` rather than a fabricated number |
| Missing dependencies | ✅ torch/web3/eventlet/shap all optional with fallbacks; `requirements-ci.txt` is the verified path |
| Port conflicts | ✅ 5000/5001/8001 free; dashboard/victim ports are env-configurable; attacker port 8001 is hardcoded (minor) |
| Race conditions | ⚠️ The previous session fixed a real non-reentrant-lock deadlock in the attacker server; no new ones observed. DB access is not transactional across threads — single-writer by design |
| Exception handling | ⚠️ 57 `except Exception` sites, several silent `pass` (defensive, but they can hide failures in logs) |
| Logging | ✅ Rich and truthful; attack, quarantine, restore, ledger and sweep are all logged |
| Persistence | ✅ SQLite schema v5 with migration of older tables; ledger chain persists and re-verifies after restart |
| Configuration | ✅ `.env.example` documents every knob; no secrets required |
| Windows compatibility | ✅ No Unix-only APIs (`fork`, `setsid`, `fcntl`, `/proc` parsing, signals-only kill); termination uses `psutil`; console scripts guard `stdout.reconfigure` |
| Restart / recovery | ✅ Restart re-primes the baseline (18 files) and continues; ledger verifies after restart |

**Resource overhead (newly measured):** idle **1.8 % CPU / 129 MB RSS**; at ~10 files/s **28 % mean CPU (110 % peak ≈ 1.1 core) / 131 MB RSS**, 43.7 MB written for 200 events. Acceptable for a laptop demo; the per-event forensic report write is the main cost.

---

## 7. Demo-readiness test (student-with-no-context procedure)

Executed as written below, from a clean state, with no prior knowledge assumed.

| Step | Command / action | Observed |
|---|---|---|
| 1 | `python main.py` | `Environment ready (version 2.0)` (optional deps reported as fallbacks) |
| 2 | `python lab.py` | Pipeline + dashboard :5000 + victim :5001 + attacker :8001 all up in ~1.2 s |
| 3 | Open dashboard `:5000` | Pipeline `online`, engine `rules`, `dry_run false`, ledger verified |
| 4 | Normal activity in `victim_server/user_files` | Events appear on the dashboard in real time, no alerts |
| 5 | Open attacker `:8001`, pick family, **LAUNCH** | `200 OK` (previously 403 — fixed) |
| 6 | Watch dashboard | Risk climbs 0.82 → 0.99 with the evidence list; incident appears |
| 7 | Watch victim `:5001` | `OPERATIONAL`, `0 encrypted`, vault locked |
| 8 | Unlock vault (`victim_user` / `1234`) | Quarantine list with real quarantined ciphertext + metadata |
| 9 | Blockchain panel | `verified: true`, `mode: local_sqlite_hash_chain`, `externally_anchored: false` |
| 10 | Tamper drill (`sqlite3` update/restore) | `verified: false` with `record hash mismatch at ledger row N`, then `true` again |
| 11 | Create a file after the incident | Processed normally, `IGNORED` — monitoring continues |
| 12 | `RESET` on the attacker console | Estate rebuilt (18 files) |

**Demo gotchas found while running this:**
- Reset state **with the lab stopped** (deleting the DB under a running pipeline logs write failures).
- The vault locks for **300 s after 5 wrong PINs** — type carefully.
- Do the ledger tamper drill **last**, and restore the original value (a broken chain makes `add()` refuse new records).
- Use `requirements-ci.txt`, not `requirements.txt` (the latter pulls torch 2.2.1 + web3 + eventlet, ~2.5 GB and not needed).
- `file_hit` count is real: the demo shows **1 file touched, 0 lost**, not "nothing ever happened".

---

## 8. "No fake 100%"

Closed in this revision (all measured, all re-verified after each fix): browser-driven attack launch; bulk-workload alert flood; post-incident inherited-evidence alert; preview-host framing/Socket.IO compatibility; ledger tamper-evidence; vault authentication.

Still open, and not to be claimed in the viva: entropy-preserving encryption is undetected; files outside the watched scope are invisible; all numbers come from synthetic fixtures; the risk score is uncalibrated (by design, labelled everywhere); the ledger is local and unanchored; the intelligence exchange is a shared file with simulated nodes; objective #21 (A/B/C baselines) is unimplemented; process monitoring is attribution-only.

---

# FINAL VERDICT

## 🟡 DEMO-READY WITH KNOWN LIMITATIONS

**1. Overall readiness percentage:** **≈ 90 %** — critical demo path 100 % (12/12 checkpoints executed and verified); objectives 79 % (13 met, 7 partial, 1 unmet); adversarial resistance 60 % (3 of 5 in-scope evasion techniques detected). The weights are stated, not measured.

**2. End-to-end test result:** **PASS** — executed three times end-to-end: attack launched from the console through the browser path, detected at 206 ms, process killed at 1.0–1.4 s, 1 file touched and restored, 0 encrypted, 3 quarantined, incident recorded, ledger verified, dashboard live, monitoring continuous.

**3. Critical failures:** none remaining. One critical (attack launch 403) and two high/medium false-positive defects were found and fixed during this audit, each re-verified. No component of the critical path fails.

**4. Remaining research gaps:** entropy-preserving (XOR-style, format-preserving) encryption undetected; no A/B/C baseline comparison (objective #21); no real-file corpus (all thresholds fitted to synthetic fixtures); similarity threshold uncalibrated; no pre-emptive/kernel-level protection; overhead not part of the automated benchmark.

**5. Security loopholes:** entropy-preserving evasion (High, open); out-of-scope files invisible (Medium, by design); console page doubles as the control credential (Low, accepted); DB-deletion under a running agent causes write failures until restart (Low, procedure issue).

**6. False-positive / false-negative results:** FP 0 (21 benchmark workloads + 227 live benign events, including a 200-file single-second burst); FN 0 on the committed battery (48/48); **but** FN on the adversarial battery: 13 files destroyed undetected (10 XOR-burst + 3 XOR-low-and-slow), plus 5 files invisible outside the watch scope.

**7. Genuinely working:** real-time monitoring; entropy + structure + sequence features; behavioural fingerprinting with measured cross-host contrast; uncalibrated multi-family risk with evidence lists; campaign escalation; verified-identity process termination with refusals; quarantine with metadata; backup restore; incident persistence; tamper-evident ledger; vault; honest dashboard; continuous monitoring after containment.

**8. Partially implemented:** process behaviour monitoring (attribution only); threat-intel exchange (local shared store, simulated nodes); immutable audit (tamper-evident, no anchor); protection of unaffected files (post-hoc); unknown-ransomware coverage (format check, no entropy-preserving coverage); overhead/latency measurement (measured here, not automated).

**9. Must be fixed before tomorrow:** nothing on the critical path — it was already executed successfully with the current code. Mandatory operational steps: verify the launch button on the actual demo machine/browser before the audience; reset state with the lab stopped; have the vault PIN ready; do the ledger drill last and restore it.

**10. Safely postponed:** A/B/C baseline comparison; real-file corpus integration; DQN removal; anchoring the ledger; canaries/pre-emptive blocking; automating the latency/overhead measurement.

**11. Exact final demo procedure:** see §7 (12 steps, all executed).

**12. Exact commands:**
```bash
cd EntropYY
python -m venv .venv && .venv/bin/pip install -r requirements-ci.txt   # Windows: .venv\Scripts\pip
python main.py            # environment health check (expect "Environment ready")
python lab.py             # starts pipeline + dashboard :5000 + victim :5001 + attacker :8001
# reset estate (lab stopped):  python victim_server/create_fake_files.py
# ledger drill:  ORIG=$(sqlite3 blockchain/ledger.db "SELECT status FROM ledger WHERE id=1;")
#                sqlite3 blockchain/ledger.db "UPDATE ledger SET status='BENIGN' WHERE id=1;"
#                ... show dashboard verified:false ...
#                sqlite3 blockchain/ledger.db "UPDATE ledger SET status='$ORIG' WHERE id=1;"
```

**13. Final statement:**

> **I have actually executed and verified the critical end-to-end workflow.**
> It was executed three times end-to-end (plus one full battery, one evasion battery, one ledger
> tamper drill and one overhead measurement). It works reliably, three real defects were found and
> fixed during the audit, and the remaining limitations are stated above rather than hidden.
