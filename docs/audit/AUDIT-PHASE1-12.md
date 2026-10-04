# EntropYY — Complete Project Audit & Redesign Proposal

**Project:** Entropy-Fingerprint Blockchain for Proactive Ransomware Defence
**Audited commit:** `31e8b1016f3318b1c8f3d1d3385dd06ff16c18eb` (single commit, branch `main`)
**Audit date:** 2026-10-04
**Auditor method:** static read of all 16,421 lines of Python + **empirical execution** (dependency install, full test suite, benchmark battery, live 4-service lab, real attack run, targeted reproduction experiments). No claim in this document is accepted from a report or a README without being executed.

> **No code has been changed.** `git status` is clean apart from this document.

---

## 0. EXECUTIVE VERDICT (read this first)

**The detection-and-response engine is real and it works. The shell wrapped around it lies.**

I proved this by running the system. When I bypass the attacker console and drive the real
attack engine directly, the full defence chain executes correctly:

```
attack start → 18 targets scanned → file 1 encrypted → file 2 encrypted
→ CAMPAIGN CONFIRMED → real SIGTERM delivered to PID 2084
→ "[attack] !! TERMINATED BY DEFENSE SYSTEM (pid=2084 killed by defender)"
→ 2 ciphertext files moved to quarantine_storage/ with .meta.json sidecars
→ 4 forensic JSON reports written → ledger entries recorded
→ post-kill verification found Tax_Returns.pdf content ≠ last clean hash → quarantined + restored
→ final estate: 18/18 files present, 0 × .WNCRY
```

That is a genuinely working proactive defence. It is not theatre.

But when I run the **documented flagship demo** (`python lab.py` → open attacker console → click
Launch WannaCry), the system **deadlocks permanently on the first click** and the attack never
starts. Separately, the dashboard and victim-explorer APIs **fabricate forensic evidence** —
inventing a process kill that never happened, a PID, an entropy value, a fingerprint, a
confidence of 100%, and an engine name that is not the engine in use. And the component the
project is *named after* — the fingerprint — is a plain SHA-256 content hash that
**provably can never match across hosts**, which makes the entire threat-intelligence layer void.

So: this is not a "rewrite everything" situation. It is a **keep the core, excise the
fabrication, build the two missing research layers** situation. That is good news, and it is
an honest, defensible path to a strong 200-mark project.

### Verdict by area

| Area | Verdict |
|---|---|
| Entropy engine | **KEEP** — correct Shannon implementation, sectioned sampling, rename-aware history |
| File monitoring | **KEEP** — watchdog + dedup + inode-reuse rejection + backpressure |
| Decision engine (rules + campaign) | **KEEP** — the campaign tracker is the best idea in the codebase |
| Response / termination safety | **KEEP** — genuinely careful, verified-identity-only, self-kill prevention |
| Backup / restore | **KEEP** — strict-clean rule and post-kill content verification are correct |
| Benchmark harness | **KEEP** — real instrumentation, numbers reproduce exactly |
| Honest limitations docs | **KEEP** — unusually good scientific practice |
| Attacker console HTTP layer | **REWRITE** — hard deadlock, plus fake-exploit theatre |
| Dashboard / explorer APIs | **REWRITE** — systemic fabrication of evidence |
| Behavioural fingerprint | **ADD** — does not exist; it is the project title |
| Threat intelligence exchange | **REWRITE** — keyed on an identifier with zero cross-host collision probability |
| Blockchain / immutable audit | **REWRITE** — a SQLite table with no chain, no hash, no signature |
| Process behaviour monitoring | **ADD** — objective #6 is not implemented at all |
| ML feature layer | **REWRITE** — 6 of 11 features do not exist at inference time |
| DQN / PyTorch | **REMOVE** — ~700 lines, no weights in repo, never the default, ~2 GB dependency |

### Quality gate: **FAILED**

| Gate item | Status |
|---|---|
| End-to-end demo works from clean environment | ❌ **FAIL** — deadlocks on first click (F1) |
| No fake results exist | ❌ **FAIL** — 19 fabrication defaults (F2, F3) |
| Behavioural fingerprinting works | ❌ **FAIL** — not implemented (F4) |
| Blockchain logging is real | ❌ **FAIL** — no chain, no tamper evidence (F5) |
| Threat intelligence workflow works | ❌ **FAIL** — mathematically void (F4) |
| SOC dashboard shows real events | ⚠️ **PARTIAL** — event feed real; counters/status/process panel fabricated |
| Real-time monitoring works | ✅ PASS |
| Entropy analysis works | ✅ PASS |
| Multi-signal detection works | ⚠️ PARTIAL — largely extension/note signature (F9) |
| Automated response works safely | ✅ PASS — verified live |
| Quarantine works | ✅ PASS — verified live |
| False positives tested | ⚠️ PARTIAL — circular synthetic data (F10) |
| Evasion scenarios tested | ⚠️ PARTIAL — 1 blind spot, no adversarial battery |
| Explainability works | ⚠️ PARTIAL — real data exists, UI corrupts it |
| Performance measured | ❌ **FAIL** — no CPU/RAM/IO/wall-clock latency anywhere |
| Failure scenarios tested | ❌ **FAIL** — health check is fail-open (F6) |
| Security testing performed | ❌ **FAIL** — vault auth removed, unauth destructive endpoint (F13) |
| Reproduction instructions work | ❌ **FAIL** — `requirements-ci.txt` cannot run the suite (F7) |
| Research contribution defensible | ❌ **FAIL** — as currently framed (F4) |
| Known limitations documented | ✅ PASS — genuinely good |

---

# PHASE 1 — COMPLETE PROJECT AUDIT

> **Phases deliberately omitted from this document.**
> **Phase 4 (base-paper comparison)** is blocked — no papers were supplied (see Phase 3). I will
> not fabricate a comparison table or invent citations.
> **Phase 7 (module-by-module implementation plan)** and **Phases 13-18 (implementation,
> integration, adversarial testing, benchmarking, documentation, demo procedure)** are the *work
> itself*, not the audit; per your instruction *"Do not start coding until the audit and
> redesigned architecture are presented"*, they follow your approval of Phase 12. The roadmap in
> Phase 12 is the sequenced plan those phases will execute.

## 1.1 Verification environment

The sandbox arrived with **zero** dependencies installed. I created `.venv` and installed
`watchdog psutil numpy flask flask-socketio python-dotenv colorama eventlet simple-websocket`,
then `scikit-learn==1.4.2 shap`. Notably absent and never installable in the default path:
`torch` (no DQN) and `web3` (no Ganache). Both are declared optional, and both defaults
therefore exercise the fallback path — which matters for F5 and F7.

## 1.2 Requirement audit table

Priority: **CRITICAL / HIGH / MEDIUM / LOW**

| # | Requirement | Expected by project | Current implementation | Working? | Evidence | Gap | Priority |
|---|---|---|---|---|---|---|---|
| 1 | One-command live demo | `python lab.py` → launch attack → observe defence | 4 services start correctly; attack launch deadlocks | ❌ | Stack trace §F1 | Non-reentrant lock self-deadlock | **CRITICAL** |
| 2 | No fake features | Zero fabricated results/alerts/data | Attacker injects fabricated detections; 15 hardcoded "success" defaults | ❌ | §F2, §F3 | Presentation layer invents evidence | **CRITICAL** |
| 3 | Behavioural fingerprint (project title) | Fingerprint of *behaviour*, comparable across events/hosts | SHA-256/SHA3-256 of file **bytes** | ❌ | §F4 | Title concept absent | **CRITICAL** |
| 4 | Threat intelligence sharing | Host A → fingerprint → Host B detects earlier | SQLite registry keyed on content hash | ❌ | §F4 (1000/1000 distinct hashes) | Identifier cannot collide | **CRITICAL** |
| 5 | Immutable audit / blockchain | Tamper-evident record | `CREATE TABLE ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, …)` | ❌ | §F5 | No hash chain, no signature, no verification | **CRITICAL** |
| 6 | Fail-safe health reporting | Detector death must be visible | `pipeline_status()` returns `online: True` unconditionally | ❌ | §F6, 2 failing tests | Fail-open | **HIGH** |
| 7 | Process behaviour monitoring (obj. #6) | Process tree, ancestry, suspicious creation, I/O | None. Reactive `psutil` lookup at file-event time only | ❌ | §F2 obj. table | Objective not implemented | **HIGH** |
| 8 | Vault / evidence access control | PIN-gated quarantine vault | `_vault_unlocked()` → `return True` | ❌ | §F3, live HTTP 200 | Auth deleted | **HIGH** |
| 9 | ML feature integrity | Features at inference = features at training | 6 of 11 RF features have no producer | ❌ | §F7 | Train/serve skew; 2 features are duplicates | **HIGH** |
| 10 | Reproducible test suite | `requirements-ci.txt` → suite passes | CI reqs omit scikit-learn; 6 tests hard-require it | ❌ | §F8 | README command cannot work | **HIGH** |
| 11 | Test claims accurate | "126 tests, 0 fail" | 145 tests, 5 fail (with sklearn) / 8F+6E (without) | ❌ | §F8 | Badge false | **HIGH** |
| 12 | Real-time SOC event feed | Live events from the engine | socket.io push of real DB rows | ✅ | live run | — | — |
| 13 | Entropy calculation | Shannon, per-file, sampled | Correct; 64 KB sample; start/middle/end thirds | ✅ | `entropy_calculator.py` | — | — |
| 14 | File monitoring | Continuous, recursive, deduplicated | watchdog 0.2 s polling + dedup + inode-reuse rejection | ✅ | live run | — | — |
| 15 | Multi-signal correlation | Correlate many behavioural indicators | Entropy + Δ + rate + ext-change + campaign (2 files/15 s) | ⚠️ | `CampaignTracker` | No process/temporal-depth signals | **MEDIUM** |
| 16 | Unknown-ransomware detection (obj. #9) | Behavioural generalisation | `silent_unknown_ext` passes via "unknown extension" heuristic; `image_blindspot` 0/6 | ⚠️ | benchmark 42/48 | Signature-dependent | **MEDIUM** |
| 17 | Legit vs malicious high entropy (obj. #8) | Distinguish ZIP/media/backups from encryption | Per-type ranges (14 extensions) + 0 false quarantines | ⚠️ | benchmark | Circular fixtures; 14.3% FP; 14-ext whitelist | **MEDIUM** |
| 18 | Automated response | Kill + quarantine + restore | Implemented and safe | ✅ | live: PID 2084 killed | — | — |
| 19 | Protect unaffected files (obj. #12) | Pre-emptive protection | Post-hoc sweep + post-kill verification only | ⚠️ | live run | No canaries, no write-blocking | **MEDIUM** |
| 20 | Explainable alerts (obj. #15) | "Why is this ransomware?" | Real `explanation` + `indicators` in DB; SHAP path exists | ⚠️ | DB rows | `/api/dqn/last` overwrites with defaults | **MEDIUM** |
| 21 | Baseline comparison (obj. #21) | Entropy-only vs hash+entropy vs behaviour-only | Absent. Only rules-vs-RF (engine vs engine) | ❌ | §Phase 10 | No architecture-level baseline | **HIGH** |
| 22 | Detection latency in time | Seconds/ms to detection | Reported in **file operations**, not wall clock | ⚠️ | benchmark output | No temporal latency metric | **MEDIUM** |
| 23 | % files affected before detection | Explicit objective | Derivable from `ops_to_detection` but never expressed | ⚠️ | recovery drill | Not reported as % of estate | **MEDIUM** |
| 24 | Resource overhead | CPU / RAM / disk-IO of the monitor | Not measured anywhere | ❌ | §Phase 10 | Objective unmet | **HIGH** |
| 25 | Adversarial testing | Attack your own detector | 8 fixed scenarios; no evasion battery | ⚠️ | `benchmark/scenarios.py` | No systematic bypass study | **HIGH** |
| 26 | Failure scenarios | Blockchain/dashboard/DB/detector down | Untested; health check fail-open | ❌ | §F6 | Fails §23 of brief | **HIGH** |
| 27 | Security of our own system | Threat model, authz, injection | Vault auth removed; unauth destructive endpoint; `cors="*"`; no dashboard auth | ❌ | §F13 | No threat model | **HIGH** |
| 28 | Process attribution accuracy | Correct responsible process | Best-effort; attributed my `timeout` wrapper as suspect | ⚠️ | ledger row: `pid 2082, 'timeout'` | Safety held; record wrong | **MEDIUM** |
| 29 | Evidence integrity | Audit trail not editable | `execute_response` rewrites whitelisted procname → `"ransomware_simulator"` | ❌ | §F12 | Fabricated provenance in evidence | **MEDIUM** |
| 30 | Dependency hygiene | Only what is needed | `torch` (unused), `eventlet` (unused, deprecated), root-level stray modules | ⚠️ | §F14 | ~2 GB dead weight | **LOW** |
| 31 | Repo/process evidence | Development trace for 200-mark evaluation | 1 commit; 11 weekly docs uncorroborated by git | ⚠️ | `git log` | Process evidence weak | **LOW** |
| 32 | Naming consistency | One project identity | Title "Entropy-Fingerprint Blockchain" / README "Ransomware Shield" / commit "Entroshield" | ⚠️ | — | Confusing to evaluators | **LOW** |
| 33 | Literature grounding | Base papers, lit review, citations | `## References` = 4 bare topic names; zero citations in the entire tree | ❌ | `docs/final-year-project.md:138`; grep for `doi\|arxiv\|et al.\|ieee` → 0 hits | No research grounding; gap never validated | **HIGH** |

---

## 1.3 FINDINGS IN DETAIL

### F1 — CRITICAL — The flagship demo deadlocks permanently on the first click

**What is wrong.** `attacker_server/app.py:47`:

```python
_proc_lock = threading.Lock()          # NON-reentrant
```

`_spawn()` (line 155) acquires it, then calls `_simulate_network_exploit()` (line 162), which
calls `_append_log()` (line 106), which acquires **the same lock on the same thread**:

```python
def _append_log(text):
    ...
    with _proc_lock:        # ← already held by _spawn on this thread
        _stream.append(entry)
```

**Proof (captured stack trace of the hung thread):**

```
File "attacker_server/app.py", line 162, in _spawn
    _simulate_network_exploit(family_id)
File "attacker_server/app.py", line 112, in _simulate_network_exploit
    _append_log("[smb] Initializing Network Exploit Module (Target: victim-pc:445)...")
File "attacker_server/app.py", line 106, in _append_log
    with _proc_lock:
```

`_proc_lock type: lock | re-entrant: False` … `_spawn returned within 5s? False`

**Why it is catastrophic, not merely annoying.** The handler thread dies holding the lock
forever. Every other route that needs it — `_child_state()` → `/api/stats`, `/api/log` — then
blocks forever too. I confirmed this live: after one `POST /api/launch`, even a plain
`GET /api/stats` did not respond within 20 s. The attacker console freezes solid; the lab is
unrecoverable without killing the process tree.

**Objective failed:** the entire demonstration (§25 of your brief); reproducibility (§24).

**Why no test caught it:** no test exercises `_spawn()` end-to-end. The theatre function
`_simulate_network_exploit()` was clearly added *after* the locking design, and nothing
re-tested the path.

**Fix:** `_proc_lock = threading.RLock()` (one line), **and** move `_simulate_network_exploit`
out of the lock — better, delete it (see F2c).

---

### F2 — CRITICAL — The attacker writes the defender's results

This is the single most damaging finding for academic integrity.

**(a) The relay.** `attacker_server/app.py:63`:

```python
def _relay_telemetry(filename, family, pid=292):
    """Sends real-time threat telemetry directly to SOC Server (5000)."""
    url = "http://127.0.0.1:5000/api/telemetry"
    payload = json.dumps({
        "filename": filename, "family": family,
        "entropy": 7.95,          # ← HARDCODED
        "action": 3,              # ← HARDCODED "quarantine"
        "pid": pid,
        "process_name": f"ransomware_{family}.exe"})
```

It is called (i) **four times immediately on attack start** (line 186-188) for
`Wedding_Photos.jpg`, `Family_Vacation.jpg`, `Tax_Returns.pdf`, `Client_Notes.docx` — before
the engine has touched anything, and for `Client_Notes.docx` which does not even exist in the
estate (the real file is `Client_Meeting_Notes.docx`); and (ii) for **every stdout line** the
engine emits that contains a `.` (line 143), with the filename *guessed by regex-splitting the
log line*.

**(b) The receiving endpoint.** `app.py:175 /api/telemetry` — **unauthenticated**, with
`cors_allowed_origins="*"` — then:

1. walks the victim estate and **`os.remove()`s the real user file**;
2. writes the literal ASCII string `"ENTROPY_ISOLATED_RANSOMWARE_CIPHERTEXT"` into
   `quarantine_storage/` as the "isolated ciphertext";
3. writes a `.meta.json` containing `"fingerprint": "a3b9f8d1e2c4567890abcdef12345678"`
   (hardcoded), `"entropy": 7.95` (from the attacker), and
   `"terminated_process": {"pid": pid, "terminated": True}`;
4. if no backup exists, writes `"Clean restored content for {name}"` as the "restored original";
5. inserts a DB event with `engine="dqn"`, `confidence=100.0`, `entropy_delta=2.5` (hardcoded),
   `explanation="Decision: TERMINATE + QUARANTINE | Threat score: 100/100 | High Entropy (7.95)"`,
   `status="QUARANTINED"`, `outcome="TERMINATED_AND_QUARANTINED"`,
   `restore_result="RESTORED_FROM_BACKUP"`;
6. `socketio.emit("new_event", row)` → **it appears on the SOC dashboard as a live detection.**

**Why this is disqualifying if left in.** The *attacker* authors the *defender's* conclusions.
An evaluator watching the dashboard cannot distinguish a genuine detection from an injected one
— and in the documented demo flow, the injected ones arrive **first**, because `_relay_telemetry`
fires before the engine has encrypted a single byte. The real engine's honest output is then
layered on top of, and visually indistinguishable from, the fabrication.

It also violates your §20 explicitly: *fake blockchain transactions, fake detection alerts,
fake ransomware events, fake SOC dashboard data, hardcoded "99% accuracy", simulated success
presented as real success.* This endpoint is all six at once.

**(c) The fake exploit.** `_simulate_network_exploit()` (line 110) prints, with staged
`time.sleep()` calls for dramatic pacing:

```
[smb] Detected service: Windows SMBv1 (srv.sys Memory Corruption Vulnerability MS17-010)
[smb] Crafting malicious SMB_COM_TRANSACTION2 buffer overflow packet...
[smb] Transmitting kernel shellcode to target memory space...
[smb] EXPLOIT SUCCESSFUL — Arbitrary kernel code execution achieved.
[smb] Spawning high-privilege NT AUTHORITY\SYSTEM payload process...
```

There is no exploit. No socket is opened. Nothing touches port 445. This is scripted fiction
presented as a real capability — and it is also the direct cause of F1.

**Credit where due:** the team clearly knew this pattern was wrong. `app.py:605
/api/demo/trigger` correctly returns `409 {"status":"rejected","error":"Demo injection
disabled. Run attack from http://127.0.0.1:8001"}`. Someone disabled one injection endpoint
and left the other one wired directly into the attack path.

**Fix:** delete `/api/telemetry`, delete `_relay_telemetry` and its two call sites, delete
`_simulate_network_exploit`. Replace with an *attack-progress* feed (the attacker may honestly
report what **it** did — files touched, bytes written) rendered in a clearly separated
"Red team" panel, never in the detection feed.

---

### F3 — CRITICAL — Systemic fabrication in the presentation layer

Every one of these is a hardcoded default that substitutes a **successful-looking value** when
the real value is missing. Line numbers are exact.

| File:line | Code | Fabricated claim |
|---|---|---|
| `victim_server/app.py:37` | `return True  # Kept unlocked for smooth lab demo` | Vault PIN authentication **does not exist** |
| `victim_server/app.py:125` | `"privileged": True` | Always privileged |
| `victim_server/app.py:198` | `"process_killed": True` | A process was killed — **unconditionally, for every entry** |
| `victim_server/app.py:199` | `"killed_pid": killed.get("pid") or 25576` | Invents PID 25576 |
| `victim_server/app.py:200` | `"killed_name": killed.get("name") or "ransomware_ryuk.exe"` | Invents a Ryuk infection |
| `victim_server/app.py:221` | `... if killed else [{"pid": 25576, "name": "ransomware_ryuk.exe"}]` | Reports a kill **when nothing was killed** |
| `victim_server/app.py:196` | `(meta.get("fingerprint") or "a3b9f8d1e2c45678")[:16]` | Invents a fingerprint |
| `victim_server/app.py:197` | `meta.get("entropy") or 7.95` | Invents an entropy reading |
| `app.py:595` | `"pid": r["pid"] or 25576` | Invents a PID |
| `app.py:597` | `"status": "killed" if r["max_action"] >= 2 else "watch"` | Reports "killed" from the **requested** action, ignoring the recorded `outcome` |
| `app.py:598` | `"entropy": r["max_ent"] or 7.95` | Invents an entropy reading |
| `app.py:538` | `engine = row["engine"] ... else "dqn"` | Claims the DQN decided |
| `app.py:541` | `confidence = ... else 100.0` | Claims 100% confidence |
| `app.py:555` | `{"name": "Outcome", "value": outcome or "QUARANTINED", "pass": True}` | Claims quarantine succeeded |
| `app.py:161-165` | `total/threats/terminated … or physical_q_count`; `"recovery": physical_q_count` | Threat, termination and **recovery** counts derived from a directory listing |
| `app.py:166-167` | `avg_entropy or 7.95`, `max_entropy or 7.95` | Invents entropy statistics |
| `app.py:98,109` | `"online": True` in **both** branches | Detector always alive (see F6) |
| `app.py:99,114` | `"engine": "dqn"` | Wrong engine, hardcoded (see below) |
| `app.py:110` | `"pid": hb.get("pid") if hb else 1024` | Invents a PID |

**Live proof of the harm.** After the real attack I ran, the database contained this row:

```python
{'action': 3, 'status': 'TERMINATED+QUARANTINED', 'requested_action': 3,
 'outcome': 'QUARANTINED+RESTORED', 'engine': 'rules', 'confidence': 0.0,
 'process_name': 'unknown', 'pid': None}
```

Process unknown, PID `None`, confidence `0.0`. Rendered through `/api/processes` this becomes:
**`{"name": "unknown", "pid": 25576, "status": "killed", "entropy": 7.95}`**. Rendered through
`/api/dqn/last` it becomes: **engine `dqn`, outcome `QUARANTINED`, confidence 100%**.

Meanwhile `/api/pipeline` reported `"engine": "dqn"` on a live system where the startup banner
printed `AI Engine : Rule-based (default)` and the log said
`[RUNNER] DQN unavailable (No module named 'torch') — using rule-based fallback`. The dashboard
misidentifies its own decision engine.

**Live proof of the vault hole:**

```
GET  /api/quarantine          (no PIN)      → HTTP 200
POST /api/vault/login {"pin":"0000"}        → HTTP 200
GET  /api/vault/status → {"unlocked": true, "privileged": true, "user": "victim_user"}
```

`victim_server/app.py` imports `secrets` and never uses it. `docs/limitations.md` claims
"Vault PIN compare_digest, session 8h, scope quarantine_only". `config.py` defines `VAULT_PIN`,
`VAULT_SESSION_HOURS`. All of it is dead. Two tests assert the correct behaviour and fail.

**Root cause — and it is a schema gap, not malice.** `save_to_db()` persists
`requested_action` and `outcome`, but **never persists `terminate_result`**. So the database
genuinely cannot answer "was a process actually killed?". The UI, needing to show something in
a "Processes killed" panel, invents it. Fix the schema and the fabrication becomes unnecessary
rather than merely forbidden.

**Fix:** (1) add `terminate_result`, `quarantine_result`, `attribution_source`,
`identity_verified` columns; (2) make every API read `outcome`, never `status`, and return
`null` — never a constant — when data is absent; (3) render `null` in the UI as
`NOT RECORDED`; (4) restore real vault auth with `hmac.compare_digest` + session expiry;
(5) add a test that greps the API layer for magic constants (this class of bug is mechanically
detectable).

---

### F4 — CRITICAL — The "fingerprint" is a content hash, and the threat-intel layer is mathematically void

Your brief anticipated this exactly: *"do not make the fingerprint merely SHA256(file). That is
file integrity hashing, not a meaningful ransomware behavioral fingerprint."* That is precisely
what it is.

`storage/hashing.py` provides `sha256_file`, `sha3_256_file`, `dual_hash_file` — all over file
**bytes**. `blockchain/fingerprint_exchange.py` keys its registry on that hash:

```sql
CREATE TABLE threat_fingerprints (fingerprint TEXT PRIMARY KEY, ...)
```

A grep for every use of "fingerprint" in the codebase returns content hashes and nothing else.
There is no behavioural component anywhere. **The central concept in the project title is not
implemented.**

**Worse: it cannot work, and I can prove it.** The project's own attack engine
(`attacker_server/ransomware_engines.py:220`) encrypts with:

```python
os.urandom(max(original_size, 1024))
```

I measured the consequence — encrypting the *same* victim file repeatedly:

```
original sha256:            9dd0f5ea35f5a722
Host-A     ciphertext:      caf473dac34f2205
Host-B     ciphertext:      a2be6e60c5a2fdae
Host-A-run2 ciphertext:     eda0ab7bf630248f

distinct hashes over 1000 encryptions of the SAME file: 1000 / 1000
```

**Collision probability: zero.** Real ransomware uses a fresh random IV/nonce per file (and per
victim), so ciphertext is uniformly random by design. A content hash of ciphertext is therefore
a random 256-bit nonce — a *unique identifier for one encryption event on one host*, which is
useful for forensics but **structurally incapable of being shared as threat intelligence**.
Host B asking "have you seen this fingerprint?" will always be told "no".

**Why the benchmark appears to contradict this.** `benchmark/exchange_simulation.py:78`:

```python
return random.Random(PAYLOAD_SEED).randbytes(PAYLOAD_SIZE)   # FIXED SEED
```

and line 242 writes those identical bytes into both tenants' estates. Every simulated tenant is
fed **byte-identical** ciphertext, so of course the hashes match and the exchange reports
`sightings=2, sources=2`. The cross-host correlation result is an artifact of the test fixture.
It does not generalise to the project's own attack engine, let alone to real malware.

**Confirmed live.** In my real single-node run, every fingerprint logged
`[EXCHANGE] fingerprint … shared (sightings=1, sources=1)` — never reaching
`EXCHANGE_CONFIRM_THRESHOLD = 2`. The consensus mechanism is unreachable in practice.

**This is the most important research finding in the audit.** It is also the opportunity: the
fix *is* the research contribution (see Phase 6).

**Fix:** define the fingerprint over **behaviour**, which is invariant across victims because
two hosts attacked by the same family traverse directories, transition extensions, and shape
entropy trajectories the same way even though their ciphertext bytes differ entirely. Quantise
→ symbolise → SimHash → Hamming-distance nearest-neighbour lookup. See Phase 6.2.

---

### F5 — CRITICAL — "Blockchain" is a SQLite table with no chain

Default configuration: `ENTROPY_BLOCKCHAIN_FALLBACK=true` (config.py), `web3` not installed.
Startup log: `[BLOCKCHAIN] Ganache not reachable: No module named 'web3'` →
`using LOCAL LEDGER fallback`. This is the state of every demo that has ever been run.

`blockchain/connector.py:LocalLedger`:

```sql
CREATE TABLE IF NOT EXISTS ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT, threatType TEXT, timestamp INTEGER, pid INTEGER,
    entropy INTEGER, processName TEXT, filePath TEXT,
    actionTaken TEXT, status TEXT)
```

There is **no `prev_hash`, no Merkle root, no digital signature, no verification routine**.
`UPDATE ledger SET status='IGNORED'` or `DELETE FROM ledger WHERE id=2` is completely
undetectable. The component that gives the project its name provides **zero tamper-evidence**
in the default run. Objective #13 (immutable audit records) is unmet.

**Credit where due — this part is honest.** `verify_chain()` returns `False` unless
`mode == "ganache"`; `get_status()` sets `is_blockchain = (mode == "ganache")`;
`/api/blockchain/status` maps `fallback → "Local SQLite ledger (not a blockchain)"`; and
`docs/limitations.md` states plainly: *"Fallback is NOT immutable chain."* Nobody is being
deceived deliberately here. But an honest label on a missing feature is still a missing
feature — and the title promises it.

**The Solidity contract is also weak for the stated purpose.** `ThreatLogger.sol`:
`logThreat` is `onlyOwner`, so it is a **single-writer append log** — no second party writes,
nobody verifies, no consensus exists to corrupt. It also stores full `filePath` and
`processName` **strings on-chain**, which is expensive in gas and, on a public ledger, leaks
internal directory structure and usernames. There is no smart-contract *logic* at all: no
reputation scoring, no fingerprint registry, no cross-node confirmation — the exchange lives in
a separate SQLite file that the chain never sees. So "blockchain" and "threat intelligence" are
two disconnected systems.

**Fix (recommended, and it strengthens the project):** make the **primary** ledger a genuine
hash-chained, HMAC-authenticated, Merkle-anchored append-only log that runs offline, and
demote Ethereum/Ganache to an **optional external anchor** for the Merkle roots. Concretely:
`entry_hash = SHA256(prev_hash || canonical_json(payload))`, plus
`tag = HMAC-SHA256(node_key, entry_hash)`, plus a Merkle root every *N* entries, plus a
`verify()` that walks the chain and reports the first divergence. Then the demo gets a
*genuinely* dramatic moment: edit one byte of the ledger on stage, run `verify()`, watch it
report `CHAIN BROKEN AT ENTRY 42`. That is real, reproducible, offline, and defensible — unlike
a Ganache dependency that is absent at every demo so far.

---

### F6 — HIGH — Fail-open health reporting

`app.py:87 pipeline_status()`:

```python
PIPELINE_STALE_SECONDS = 8.0        # defined at line 85, NEVER USED ANYWHERE

if not hb:
    return {"online": True, "age_seconds": 0.0, ..., "engine": "dqn", ...}   # never ran → ONLINE
age = max(0.0, time.time() - float(hb["heartbeat"]))                          # computed...
return {"online": True, "age_seconds": round(age, 1), ...}                    # ...and ignored
```

`online` is `True` in **both** branches. `age_seconds` is computed and never compared to
`PIPELINE_STALE_SECONDS`. Two tests assert the correct behaviour and fail:
`test_offline_when_pipeline_never_ran`, `test_stale_heartbeat_is_offline`.

**Consequence.** Kill the detector mid-demo and the SOC dashboard continues to report
`MONITORING`. This is the precise failure scenario your §23 asks about ("detector crashes",
"malicious process kills the detector") and the system **fails open** — the worst possible
direction for a security product. Ransomware that kills the defender first is a real and common
TTP (T1562.001 Impair Defences), and this system would not notice.

It also makes `README.md`'s own troubleshooting section wrong: it instructs examiners to look
for a `DETECTION PIPELINE OFFLINE` banner and to `curl /api/pipeline`, but that state is
unreachable.

**Fix:** `online = hb is not None and age <= PIPELINE_STALE_SECONDS`; report
`engine`/`dry_run`/`pid` from the heartbeat (which already stores them — `write_pipeline_heartbeat`
takes `dry_run`, `engine`, `pid`); render `OFFLINE (last heartbeat 42s ago)` in red; add a
tamper-evident "defender liveness" record to the audit chain so a killed defender leaves a gap
that is itself detectable.

---

### F7 — HIGH — ML train/serve skew: 6 of 11 features do not exist at inference

`ai/rf_model.py:68` declares 11 features. I grepped every producer module
(`monitoring/`, `response/`, `entropy/`, `storage/`) for each:

| Feature | Producers outside `ai/` | Reality at inference |
|---|---|---|
| `entropy_score` | ✅ | real |
| `entropy_delta` | ✅ | real |
| `files_per_sec` | ✅ | real |
| `ext_changed` | ✅ | real |
| `in_normal_range` | ✅ (computed) | real |
| `process_age_sec` | **0** | `process.get("age_seconds") or 300.0` → see below |
| `is_signed` | **0** | `1.0 if proc_name in WHITELISTED_PROCESSES else 0.0` |
| `files_affected` | **0** | aliased to `events_in_window` |
| `avg_entropy_hist` | **0** | `= entropy_score` when caller passes nothing |
| `is_known_process` | **0** | `is_known = is_signed` — **literal duplicate** |
| `time_hour` | **0** | derived from timestamp, defaults to `12.0` |

Three specific defects:

1. **`process_age_sec` is a constant exactly when it matters.** `age_seconds` is set *only* in
   `_find_recent_suspicious()` (`watchdog_monitor.py:153`) — the **unverified guess** path. The
   verified `open_file` path (lines 104-110) does not set it. So when attribution is verified
   and a response is actually taken, the feature is the default `300.0`. Training data used
   `rng.uniform(1, 300)` for ransomware and `rng.uniform(300, 7200)` for legitimate — meaning
   every real inference lands **exactly on the training decision boundary** of the
   **3rd most important feature** (importance `0.1299`, per the weights file).
2. **`is_signed` is misnamed.** It means "process name appears in a 13-entry hardcoded
   whitelist", not "binary carries a valid Authenticode signature". Presenting it to an
   evaluator as a code-signing feature would not survive a viva question.
3. **Two of eleven features are the same number.** `is_known = is_signed`, and
   `avg_entropy_hist = entropy_score`. The "11-feature explainable model" is really ~8 distinct
   signals, two of which are proxies. SHAP explanations computed over collinear duplicated
   features split importance between the copies and are therefore misleading.

**Dependency defect.** `requirements-ci.txt` — described as *"Guaranteed to install in
offline/restricted environments"* — omits `scikit-learn`, but `tests/test_rf_classifier.py`
hard-requires it. Result in a clean environment: **6 errors** (`RuntimeError: scikit-learn is
required to train the Random Forest (No module named 'joblib')`). The README's
`pip install -r requirements-ci.txt && python -m unittest discover -s tests` cannot pass.

**What is genuinely good here:** `ai/rf_weights.json` is a **real** trained artifact — 381 KB,
a genuine base64-pickled `RandomForestClassifier`, `n_train=600`, `schema_version=2`,
`sklearn_version=1.4.2`, and an honest provenance note: *"Training data is synthetic (seeded,
versioned). Measured detection/false-positive numbers come from the benchmark battery, not this
file."* That is the right way to document a model. The training data is *independently*
generated from the benchmark scenarios (`_sample_ransomware` vs `scenarios.py`), so the RF's
48/48 is not direct leakage — though both encode the same author's assumptions about what
ransomware looks like, which I would call **shared-assumption bias** and disclose.

**Fix:** emit the missing features from the pipeline for real (process age from `create_time` on
*both* attribution paths; files-affected from the campaign tracker; entropy history mean from
`EntropyAnalyzer.entropy_history`), rename `is_signed` → `process_in_allowlist`, delete the
duplicate `is_known_process`, retrain, and add a **schema-contract test** that asserts the
feature vector built from a live pipeline event has the same distribution as the training
vector (a train/serve skew test — cheap, and it would have caught this).

---

### F8 — HIGH — Test and badge claims do not match reality

| Claim | Source | Measured |
|---|---|---|
| "tests — 126 pass" | README badge | **145 tests collected** |
| "0 fail" | README, `docs/limitations.md` ("126 tests pass") | **5 fail** (with sklearn) / **8 fail + 6 error** (without) |
| "`requirements-ci.txt` … guaranteed to install" | requirements-ci.txt | omits a hard test dependency |

The 5 genuine failures map 1:1 onto real defects, which is actually a compliment to the test
suite — it was written to catch exactly these bugs, and the bugs were introduced afterwards:

| Failing test | Underlying defect |
|---|---|
| `test_locked_without_pin` | F3 — vault auth removed |
| `test_wrong_pin_rejected` | F3 — vault auth removed |
| `test_offline_when_pipeline_never_ran` | F6 — fail-open health |
| `test_stale_heartbeat_is_offline` | F6 — fail-open health |
| `test_default_watch_folder_is_confined_to_test_data` | stale test: `config._watch_folders()` now also returns `VICTIM_USER_FILES`; test not updated |

One further test — `test_same_seed_produces_identical_files` — **fails only under full-suite
ordering** and passes standalone. That is test-isolation pollution: the suite shares on-disk
state. Root cause is `config.py:104`, which calls `os.makedirs()` on **seven** directories at
**import time**:

```python
for d in [LOG_DIR, QUARANTINE_DIR, TRAINING_DATA_DIR, TESTING_DATA_DIR,
          VICTIM_USER_FILES, BACKUP_DIR, REPORTS_DIR]:
    os.makedirs(d, exist_ok=True)
```

Merely importing `config` mutates the filesystem and the shared estate. Any test that assumes a
clean tree is at the mercy of test order.

**Fix:** update the stale test; move directory creation into an explicit `ensure_directories()`
called from entry points only; give every test its own `tmpdir` and an injected `DB_PATH`.

---

### F9 — MEDIUM — Detection is largely signature matching, not behavioural

`catalog.py` hardcodes 10 real ransomware families with their exact lock extensions
(`.wncry`, `.ryk`, `.maze`, `.revil`, `.abcd`, `.alphv`, `.akira`, `.clop`, `.qilin`,
`.lockbit`) and their exact ransom-note filenames (`@Please_Read_Me@.txt`, `RyukReadMe.html`,
`Restore-My-Files.txt`, …). `family_from_filename()` matches on those. `defense_guard` +
`ransom_note.detect_ransom_note()` match filenames and phrase lists. `make_decision()` and
`DecisionEngine._base_decide()` treat `ransom_note` or `defense_tamper` as **instant
TERMINATE+QUARANTINE with confidence 1.0**, bypassing every learned engine.

Meanwhile all ten "families" are **one simulator with ten skins**: every engine subclasses
`BaseRansomware` and inherits the identical `modify_file()` = `os.urandom()` overwrite + rename.
They differ only in extension string, delay profile, and note text.

So the honest description of the headline capability is not "detects 10 ransomware families" but
"**detects 10 hardcoded file extensions and 10 hardcoded note filenames**". Against a genuinely
novel family using an unseen extension and unseen note wording, the strongest signals vanish and
detection falls back to entropy + rate + campaign — which is real, but is a materially weaker
position than the README implies.

Note the inversion in `silent_unknown_ext` (6/6 detected): it succeeds *because* the extension
is absent from `NORMAL_ENTROPY_RANGES`, so `threat_score += 40`. The detector is not
generalising behaviourally; it is treating "extension I don't recognise" as suspicious. That
heuristic cuts both ways — see F10.

**Objective impact:** #9 (detect unknown/modified ransomware) is **weak**; #7 (correlate
multiple behavioural indicators) is **partial**.

**Fix:** this is what the behavioural fingerprint layer (Phase 6.2) is for — it must fire on
*shape of activity*, with extension/note signatures demoted to **one corroborating signal among
many**, never a standalone confirmation.

---

### F10 — MEDIUM — Evaluation circularity: the test data was built to fit the thresholds

The 18-file estate is generated by `victim_server/create_fake_files.py`. The "images" and
"archives" are not images or archives:

```python
def make_binary_content(size_kb):
    """Create fake image/zip content — realistic file structure"""
    header = b'\x89PNG\r\n\x1a\n' + b'\x00' * 8            # PNG magic... in files named .jpg
    body = bytes([i % 128 for i in range(size_kb * 1024)])  # 128-value ramp
    return header + body
```

`bytes([i % 128 …])` is uniform over exactly 128 symbols, so entropy = log₂(128) = **7.00
exactly**. Measured fixtures: `.docx` 7.14, `.xlsx` 7.29, `.zip` 7.00, `.jpg` 7.00 — every one
sitting inside the `NORMAL_ENTROPY_RANGES` that the same author configured (`.jpg` 7.0-7.8 —
the fixtures land on the bottom edge of the range).

I built genuinely realistic files for comparison:

| Sample | Measured H | Configured range |
|---|---|---|
| Real `.docx` (Office Open XML ZIP container, deflate) | **6.69** | `.docx` 6.0-7.5 ✅ |
| Real `.zip` (same deflate archive) | **6.69** | `.zip` 7.5-8.0 — **below range** |
| Random / encrypted-looking | **7.99** | — |
| Repo fixture `Wedding_Photos.jpg` | 7.00 (PNG magic, `i%128` ramp) | `.jpg` 7.0-7.8 |

Two conclusions:

1. **The fixtures are not representative.** Real JPEG/MP4/ZIP/7z content reaches 7.9-8.0;
   real small deflate archives can be *below* the configured `.zip` floor. The estate's entropy
   profile was, whether deliberately or not, tuned to sit inside the detector's own ranges.
   "0 false quarantines" is therefore measured on data chosen to produce that result. That is
   not fraud — but it is **not evidence** of a real-world false-positive rate, and an evaluator
   who points the monitor at their own photo library will see different behaviour.
2. **The whitelist is the real FP surface, and it is only 14 extensions long.** Any
   high-entropy file whose extension is *not* in `NORMAL_ENTROPY_RANGES` scores +40 → ALERT.
   Absent from the list: `.gz .tar .7z .rar .bz2 .xz .bak .sqlite .db .iso .img .mp3 .flac
   .avi .mov .mkv .heic .webp .jar .war .whl .parquet .enc .gpg .age`. A `tar.gz` backup job or
   a `pip download` cache would light up the dashboard. The benchmark already shows this:
   `git_burst` alerts **3/3** runs (legit FP rate 14.3%).

**Fix:** build a **real-file corpus** (genuine JPEG/PNG/MP4/ZIP/7z/TAR.GZ/PDF/DOCX/XLSX/SQLite,
sourced or generated with real encoders), measure its true entropy distribution, **derive**
`NORMAL_ENTROPY_RANGES` from that measurement instead of hand-picking it, and report the
derived ranges in the thesis as empirical data. Replace the `i % 128` fixtures with real
encoded media. This single change converts a circular evaluation into a defensible one — and it
also fixes a latent bug: a magic-byte/format validator (needed for F11) would currently flag the
*clean* estate, because `Wedding_Photos.jpg` contains PNG magic.

---

### F11 — MEDIUM — The known blind spot is real, structural, and honestly published

`image_blindspot` — in-place encryption of already-high-entropy media without a rename —
scores **0/6**. The rule engine cannot see it: entropy stays inside the `.jpg`/`.mp4` range,
there is no rename, and the delta is small. The RF catches **6/6** but produces **6 false
quarantines** on legitimate media, so it cannot be the default.

This is documented openly in `README.md`, `docs/limitations.md` and the benchmark report, with
the correct diagnosis: *"No entropy-only detector can catch it."* That honesty is a strength and
should be preserved.

But the *fix* is not a better entropy threshold — that is the trap. It is **content provenance**:

- **Format validation:** does the file still parse as the format its extension claims? An
  encrypted JPEG fails JPEG SOI/EOI and Huffman-structure checks; an encrypted DOCX fails ZIP
  central-directory parsing. This signal is *orthogonal to entropy* and therefore immune to the
  blind spot — and to entropy-sharing evasion.
- **Hash-vs-baseline with no legitimate writer:** content changed, but no verified process holds
  a write handle and no known application owns the extension transition.
- **Canary files** (see Phase 6.4): planted decoys in every directory that no legitimate
  workload ever opens. Any write to a canary is near-certainly malicious, regardless of entropy.
  This is cheap, and it is the most demonstrable single addition available.

Note the synergy with F10: the repo's own fixtures already have a PNG header in a `.jpg`, so a
format validator would immediately flag the clean estate — fixing the fixtures and adding format
validation solve both problems at once, and produce a compelling demo (validator catches the
blind-spot attack that entropy misses).

---

### F12 — MEDIUM — Process attribution is unreliable, and the evidence trail is edited

**Live evidence of mis-attribution.** From the ledger after my real attack:

```python
{'id': 1, 'fingerprint': '2e69745ba240…', 'pid': 2082, 'processName': 'timeout',
 'filePath': '…/Financial_Report_2024.xlsx.WNCRY', 'actionTaken': '1', 'status': 'ALERTED'}
{'id': 2, 'fingerprint': 'fab017061a3b…', 'pid': 2084, 'processName': 'python', …,
 'actionTaken': '3', 'status': 'TERMINATED+QUARANTINED'}
```

Row 1 attributes the malicious write to **PID 2082, process `timeout`** — my *shell wrapper*,
not the malware. `_find_recent_suspicious()` picks "the youngest non-whitelisted process", and
on any real desktop the youngest process is usually something innocent: a browser tab, a shell,
an indexer, a language server.

**The safety layer held.** Every unverified attribution logged
`[SAFE] Process attribution is best-effort; automatic termination refused`, and the campaign
`kill_override` mechanism then killed the *correct* PID 2084. This design is right and should be
kept. But the **recorded attribution is wrong**, and wrong attributions end up in forensic
reports and on the blockchain ledger — which is worse than no attribution, because it looks
authoritative.

**Evidence tampering.** `pipeline_runner.py:execute_response`:

```python
if procname in config.WHITELISTED_PROCESSES:
    procname = "ransomware_simulator"
    pid      = None
```

Before persisting, the code **rewrites** a whitelisted process name to the literal string
`"ransomware_simulator"`. The audit record no longer reflects what was observed. Whatever the
intent (avoid labelling `explorer.exe` as malware), the effect is that the forensic trail is
edited — and in a project whose thesis is *immutable, tamper-evident audit*, the defender
editing its own audit records is the wrong optic. If the attribution is untrusted, persist
`attribution_source='whitelisted_name_discarded'` and keep the observed value.

**Fix:** persist `attribution_source` and `identity_verified` with every event; never overwrite
observed values; display unverified attributions in the UI as `SUSPECTED (unverified)` and
exclude them from "processes killed" counts entirely.

---

### F13 — HIGH — Security review of our own system

| Issue | Location | Severity |
|---|---|---|
| Vault authentication deleted (`return True`) | `victim_server/app.py:37` | **HIGH** |
| Unauthenticated **destructive** endpoint: `/api/telemetry` deletes victim files on any POST | `app.py:175` | **CRITICAL** |
| `cors_allowed_origins="*"` on the SOC app — any web page the examiner visits can POST to it | `app.py:35` | **HIGH** |
| **No authentication at all** on the SOC dashboard `/` or any `/api/*` | `app.py` | **HIGH** |
| Inversion: the *attacker* console is properly token-gated (`hmac.compare_digest`, `control_authorized`) while the *defence* surface is open | `attacker_server/app.py:429` | — |
| Hardcoded default credentials in source: `SECRET_KEY="entropy-local-development-only"`, `VAULT_PIN="1234"`, `VAULT_USER="victim_user"` — and printed by `lab.py` and README | `config.py:186-190`, `lab.py:86` | **MEDIUM** |
| Log/DOM injection: filenames, process names and cmdlines are logged and rendered with no sanitisation. A file named with newlines/ANSI escapes forges log lines; an HTML-bearing filename can inject into the dashboard | `pipeline_runner`, `dashboard.html` | **MEDIUM** |
| Path handling: `/api/reports/<path:name>` passes a user-controlled path segment to `load_report()` — needs an explicit allowlist/`realpath` containment check | `app.py:444` | **MEDIUM** |
| Quarantine read-only enforced only by POSIX permissions, checked via `os.access(W_OK)` in tests — bypassed when running as root (common in containers/CI) | `response_module.py` | **LOW** |
| `ATTACKER_HOST = "0.0.0.0"` — attack console on all interfaces | `config.py:170` | **LOW** (token-gated) |
| Import-time filesystem side effects (`os.makedirs` × 7) make isolation and safe testing hard | `config.py:104` | **LOW** |
| **Fail-open** health reporting (F6) | `app.py:87` | **HIGH** |
| Fail-**closed** response layer — refuses unverified kills, own PID, PID<10, whitelisted names | `response_module.py:117` | ✅ correct |
| Symlink handling: `_find_by_open_file` uses `os.path.realpath` (good), but quarantine move does not verify the target is not a symlink out of the estate | `response_module.py` | **MEDIUM** |

**Fix:** delete `/api/telemetry`; set `cors_allowed_origins` to the known lab origins; add token
auth to the SOC API (mirror the attacker console's existing, correct pattern); load credentials
from env with a hard failure if unset in non-dev mode; sanitise all filenames before logging and
escape on render; add `realpath` containment to every path-taking route; verify quarantine
sources are regular files, not symlinks.

---

### F14 — LOW — Repository hygiene and duplication

- **Root-level strays:** `main.py` (dependency health check), `install.py`, `reset_test.py`,
  `test_blockchain.py` (a test outside `tests/`, so `discover -s tests` never runs it),
  `entropy_system.py` and `blockchain/blockchain_logger.py` (deprecation facades emitting
  `DeprecationWarning`). In a repository with **one commit** and no external consumers, there is
  nothing to be backward-compatible *with*. `docs/architecture.md` even labels them
  "Compatibility Facades (Do Not Extend)". **Remove.**
- **`torch==2.2.1` + `shap`** in `requirements.txt` — a multi-GB install — for a DQN that has
  **no weights in the repo** (`ai/*.pth` is gitignored), is never the default
  (`AI_ENGINE="auto"` → rules), and logs `DQN unavailable` on every single startup.
  `ai/dqn_model.py` is **711 lines of dead code**. **Remove** (or commit real weights and make it
  earn its place — but see Phase 8: I recommend removing).
- **`eventlet==0.35.2`** pinned while `SocketIO(async_mode="threading")` is used. Eventlet is
  unused *and* deprecated upstream (it prints a deprecation warning on import in every log I
  captured). **Remove.**
- **`requirements.txt` pins are stale** relative to a working install: I installed current
  `scikit-learn 1.4.2` with `shap 0.51.0`, whereas `docs/limitations.md` claims shap 0.51
  conflicts with numpy 1.26.4 and caused `ResolutionImpossible`. That conflict appears resolved
  or avoidable; the pinning note should be re-verified.
- **Single-commit history** ("Add complete Entroshield project") with 11 detailed weekly progress
  documents that git cannot corroborate. For a 200-mark evaluation that rewards *process*, this
  is a real lost opportunity — the weekly docs are good, but the commit graph shows nothing.
- **Three project names:** title "Entropy-Fingerprint Blockchain", README H1 "ENTROPY —
  Ransomware Shield", commit message "Entroshield", `app.py:70` `"product": "ENTROPY"`.
  Pick one.

---

# PHASE 2 — OBJECTIVE ALIGNMENT AUDIT

Against the 21 objectives in your brief. **Score: 4 fully met, 10 partial, 7 not met.**

| # | Objective | Status | Evidence / gap |
|---|---|---|---|
| 1 | Detect ransomware early | ⚠️ PARTIAL | Kills at file 2-3 of 18 — genuinely early. But "early" is measured in *file operations*, never in wall-clock time |
| 2 | Continuously monitor file activity | ✅ MET | watchdog 0.2 s polling, recursive, dedup, verified live |
| 3 | Calculate entropy | ✅ MET | Correct Shannon; 64 KB sample; start/middle/end thirds for partial encryption |
| 4 | Generate file/**behavioural** fingerprints | ❌ **NOT MET** | Content hash only (F4). The project title's core concept is absent |
| 5 | Detect suspicious encryption behaviour | ⚠️ PARTIAL | entropy + Δ + rename + rate + campaign. No format validation, no write-amplification, no read:write ratio |
| 6 | Monitor **process** behaviour | ❌ **NOT MET** | No process monitoring exists. Only reactive `psutil` lookups at file-event time. No ancestry, no process tree, no image loads, no I/O counters, no creation auditing. The one proactive piece is a cmdline signature scan for `vssadmin`/`wbadmin`/`net stop` (Windows-only strings, on a Linux demo) |
| 7 | Correlate multiple behavioural indicators | ⚠️ PARTIAL | `CampaignTracker` (≥2 files with encrypted signature in 15 s) is real and is the strongest existing correlation. But indicators are few and the "encrypted signature" gate is entropy+Δ/ext-change |
| 8 | Distinguish ransomware from legit high-entropy ops | ⚠️ PARTIAL | Per-type ranges give 0 false quarantines on *synthetic* data; 14.3% alert FP; 14-extension whitelist; circular fixtures (F10) |
| 9 | Detect unknown/modified ransomware | ⚠️ WEAK | `silent_unknown_ext` 6/6 but via "unrecognised extension" heuristic; `image_blindspot` 0/6; family detection is extension/note signature (F9) |
| 10 | Provide automated response | ✅ MET | Verified live end-to-end |
| 11 | Stop/quarantine malicious processes safely | ✅ MET | Real SIGTERM on PID 2084; strong safety gates; dry-run; whitelist; self-kill prevention |
| 12 | Protect unaffected files | ⚠️ PARTIAL | Post-hoc only: campaign sweep + post-kill verification. **No pre-emptive protection** — no canaries, no write-blocking, no directory-level lockdown |
| 13 | Maintain **immutable** audit records | ❌ **NOT MET** | SQLite table, no chain/hash/signature/verification (F5) |
| 14 | Threat intelligence sharing | ❌ **NOT MET** | Keyed on random ciphertext hash; 1000/1000 distinct; unreachable consensus threshold (F4) |
| 15 | Explainable alerts | ⚠️ PARTIAL | Real `explanation` + `indicators` lists in the DB; SHAP path exists. But `/api/dqn/last` overwrites engine→`dqn`, confidence→`100.0`, outcome→`QUARANTINED` (F3) |
| 16 | Real-time SOC dashboard | ⚠️ PARTIAL | socket.io push of real DB rows works. Counters, threat level, process panel, pipeline status and vault are fabricated (F3, F6) |
| 17 | Measure detection accuracy | ✅ MET | Benchmark reproduces exactly: rules 42/48 (87.5%), RF 48/48 |
| 18 | Measure false positives | ⚠️ PARTIAL | Measured (14.3% alert FP, 0 false quarantine) but on circular synthetic data (F10) |
| 19 | Measure detection **latency** | ❌ **NOT MET** | Reported in file operations only. No wall-clock ms. No end-to-end event→decision→response timing |
| 20 | Measure % files affected before detection | ⚠️ PARTIAL | Derivable (`ops_to_detection`, recovery drill) but never expressed as % of estate |
| 21 | Compare against meaningful **baselines** | ❌ **NOT MET** | No Baseline A (entropy-only), B (hash+entropy), C (behaviour-only). Only rules-vs-RF, which is engine-vs-engine within one architecture — it cannot demonstrate that the *architecture* is better |

**Also entirely absent from the codebase**, all required by your brief:

- CPU / RAM / disk-I/O overhead measurement of the monitor itself (§22) — *nothing*
- Adversarial battery: attack your own detector (§15) — *nothing beyond 8 fixed scenarios*
- Failure-injection tests: blockchain down, dashboard down, DB failure, detector killed, disk
  full, permissions denied, 10k-file burst (§23) — *nothing*
- Threat model of our own system (§21) — *nothing*
- Cross-host threat-intel demonstration Host A → Host B (§11) — *simulated with identical
  byte-for-byte payloads, which is the artifact described in F4*

---

# PHASE 3 — RESEARCH-GAP ANALYSIS

> ⚠️ **BLOCKED — materials required.** Your brief lists a major-project report, Phase-I report,
> synopsis, literature review, base/research papers and architecture diagrams as inputs. **None
> of these are in the repository.** The only research-adjacent documents present are the
> project's own `docs/*.md` (11 weekly logs, architecture, pitch, limitations, benchmark and
> recovery reports).
>
> The one `## References` heading in the repo (`docs/final-year-project.md:138`) contains four
> bare topic names and **zero actual citations** — no authors, titles, years, venues, DOIs or
> URLs:
>
> ```
> ## References
> - Shannon entropy
> - NIST SHA3-256
> - MITRE ATT&CK T1486
> - Flask-SocketIO, watchdog, psutil
> ```
>
> I grepped the entire tree for `doi|arxiv|et al.|ieee|acm|springer|bibliography|citation`:
> no academic reference exists anywhere. For a 200-mark major project this is itself a finding —
> there is currently **no literature grounding at all**, which is why the research gap has never
> been validated against prior work.
>
> I can therefore analyse the **research gap in the code**, which I have done below, but I
> **cannot** do the base-paper comparison table (Phase 4), and I will not invent one. Doing so
> would violate your own rule: *"Never fabricate research results, accuracy, latency, detection
> rates, or citations."* Please supply the papers and I will complete Phases 3 and 4 properly.

## 3.1 The gap the code actually reveals

Your brief asks the decisive question: *"If ransomware intentionally avoids producing obvious
high-entropy patterns, will our system still detect it?"*

**Answer, measured: NO — and the project already knows it.** `image_blindspot` is 0/6 with the
rule engine. The same is true for any entropy-masking strategy: partial encryption, appending
ciphertext to plaintext, low-entropy-looking encodings, or encrypting only the first N KB.

The current architecture has a **single point of failure dressed as a multi-signal system**. Look
at what actually gates every destructive decision in `make_decision`:

```python
corroborated = ext_chg or hi_speed or delta_signal     # delta_signal = |Δentropy| >= 2.0
if score >= 70 and corroborated: return TERMINATE_QUARANTINE
```

and in `CampaignTracker._qualifies`:

```python
if ent < config.ENTROPY_THRESHOLD: return False        # HARD GATE on entropy
return (delta >= ENTROPY_DELTA_THRESHOLD or ext_changed)
```

**Entropy is a mandatory precondition, not one signal among many.** If entropy stays low, the
campaign tracker never admits the file, `score` never reaches 70, and nothing escalates. Rename
and rate can corroborate but cannot originate. So the system is *entropy-primary with behavioural
decoration* — the exact reduction your brief forbids ("entropy → threshold → ransomware … is NOT
sufficient").

## 3.2 Research Gap Matrix (from code + measured evidence only)

| Existing approach (as implemented here) | Limitation (measured) | Our solution | Evidence we can produce | Remaining gap |
|---|---|---|---|---|
| Shannon entropy + per-type range | Blind to in-place encryption of high-entropy media: **0/6** | Add format validation + hash-vs-baseline + canaries, orthogonal to entropy | Re-run `image_blindspot` after fix | Adversary that produces *valid* format structure while encrypting payload |
| Entropy Δ vs per-file history | Requires a prior observation; useless on first-touch of a new file; defeated by slow incremental change | Population/directory-level entropy distribution drift, not just per-file | New "low-and-slow" and "cold-start" scenarios | Slow enough + spread wide enough still approaches the noise floor |
| Event rate ≥ 3/s | Slow attacks evade entirely (documented) | Rate is one of many; burstiness (Fano factor), inter-event regularity, sequential-walk score | Slow-crawler + intermittent scenarios | A patient attacker below all temporal thresholds |
| Extension-change detection | Signature list of 10 known extensions; rename-optional ransomware defeats it | Extension-*transition* distribution vs per-directory baseline; no name list | Novel-extension + extension-preserving scenarios | Attacker that mimics a legitimate transition (`.tmp`→`.docx`) |
| Ransom-note filename/phrase signatures | Unknown note wording with no matching filename is invisible (documented) | Note detection demoted to corroborating signal only | New note-wording scenarios | — |
| Content-hash fingerprint + exchange | **Zero cross-host collision probability** (1000/1000 distinct) | Behavioural SimHash fingerprint, invariant to per-victim randomisation | Host A → Host B with *independently randomised* ciphertext — the honest version of the current test | Behavioural drift between family versions; deliberate mimicry |
| SQLite "ledger" | No tamper evidence whatsoever | Hash-chained + HMAC + Merkle-anchored; Ethereum optional anchor | Byte-flip on stage → `CHAIN BROKEN AT ENTRY n` | Key management for the HMAC node key |
| Youngest-non-whitelisted-process attribution | Attributed my `timeout` wrapper as the attacker (live) | Attribution confidence field; open-handle + ancestry + creation-time correlation; canary-triggered attribution | Measured attribution accuracy across scenarios | User-mode attribution on Linux without eBPF is inherently best-effort |
| Rules vs RF comparison | Not an architecture comparison | Baselines A/B/C vs proposed, same corpus, same metrics | Full comparison table | — |

## 3.3 What our project **cannot** solve (scientific honesty, required by your §26)

- **Cannot** detect ransomware that produces no observable filesystem change in a watched
  directory (e.g. encrypting only unwatched paths, or operating purely in memory before a single
  flush).
- **Cannot** recover files that were never backed up, or that existed only in encrypted form. The
  recovery drill measures this honestly: **111/246 recovered (45.1%), 123 lost**. Recovery is
  *restoration from a pre-attack clean copy*, never decryption. This is correctly documented and
  must stay that way.
- **Cannot** decrypt quarantined ransomware output. The simulator overwrites with `os.urandom()`
  and destroys the original; there is no key. `docs/limitations.md` says this bluntly and is
  right to.
- **Cannot** guarantee attribution of a file write to a process from user space on Linux without
  kernel tracing. `psutil.open_files()` is a poll, not an event; a fast writer closes the handle
  before the 0.2 s poll observes it. This is a hard platform limit, not a bug.
- **Cannot** claim zero-day detection. Behavioural generalisation to *unseen* families is
  testable and defensible; "detects all zero-day ransomware" is not.
- **Cannot** claim zero false positives. Any detector sensitive enough to catch low-and-slow
  encryption will alert on some legitimate bulk operation. The defensible claim is a *measured,
  bounded* FP rate with a *measured* cost per false quarantine.
- **Is not** production endpoint protection. It is a controlled purple-team lab. `app.py:75`
  already says this correctly: *"Purple-team range for SOC training — not an EDR replacement."*
  Keep that sentence.
- **Cannot** validate Windows-specific TTPs (`vssadmin`, `wbadmin`, Shadow Copy deletion) on the
  Linux demo environment. `TAMPER_CMDLINE_SIGNATURES` are Windows command strings that will never
  match on the platform the project is demonstrated on. Either demonstrate on Windows or replace
  with the platform-appropriate equivalents and say which.

---

# PHASE 5 — EXISTING ARCHITECTURE vs YOUR 9-LAYER MODEL

| Your layer | Present? | Where | Verdict |
|---|---|---|---|
| L1 File Integrity Monitoring | ✅ | `watchdog_monitor`, `backup_manager` hash baseline | **KEEP** + add symlink/magic-byte validation |
| L2 Entropy Analysis | ✅ | `entropy_calculator` (Shannon, thirds, per-type range, Δ) | **KEEP** + add multi-scale/windowed entropy, entropy slope & variance, byte-histogram KL divergence |
| L3 Temporal Behaviour | ⚠️ partial | `SpeedTracker` (10 s window), `entropy_history` deque(10), `CampaignTracker` (15 s) | **MODIFY** — no slope, variance, burstiness, periodicity, or per-process time series |
| L4 Process Behaviour | ❌ **absent** | reactive `psutil` lookups only | **ADD** — process tree, ancestry, creation events, I/O counters, cmdline, attribution confidence |
| L5 Behavioural Fingerprinting | ❌ **absent** | — | **ADD** — the project's namesake. See Phase 6.2 |
| L6 Risk Scoring / ML | ⚠️ broken | rules + campaign (good), RF (skewed, F7), DQN (dead) | **REWRITE** feature layer; **REMOVE** DQN; keep rules as the auditable floor |
| L7 Threat Intel Correlation | ❌ void | `fingerprint_exchange` (content-hash keyed) | **REWRITE** on behavioural fingerprints; real 2-node demo with independent randomisation |
| L8 Response Decision Engine | ✅ good | `make_decision`, `DecisionEngine`, `response_module`, `backup_manager` | **KEEP** + add explicit policy config, protected-process list file, high-risk confirmation, rollback |
| L9 Immutable Audit / Blockchain | ❌ in name only | `LocalLedger` SQLite table | **REWRITE** — hash chain + HMAC + Merkle; Ethereum as optional anchor |
| *(cross-cutting)* SOC dashboard | ⚠️ | `app.py`, `dashboard.html` | **REWRITE** the API surface; keep the socket.io transport and layout |
| *(cross-cutting)* Demo harness | ❌ | `attacker_server/app.py` | **REWRITE** — deadlock + fabrication |
| *(cross-cutting)* Benchmark | ✅ excellent | `benchmark/runner.py`, `scenarios.py`, `recovery_drill.py` | **KEEP** + extend (baselines, adversarial, wall-clock, resource overhead) |

---

# PHASE 6 — PROPOSED ARCHITECTURE

## 6.1 Design principle

**Entropy becomes one signal of ~12, and no signal is a hard gate.** Every destructive decision
requires a *risk score* assembled from independent evidence families, and at least one signal
from **two different families** (content / temporal / process / structural / provenance). A
signal may be strong enough to *alert* alone; nothing may *quarantine* alone except a canary
write (which is by construction near-certain evidence) — and even that is configurable.

## 6.2 The behavioural fingerprint (the actual research contribution)

**Definition.** For a session *S* = (attributed process, time window, directory scope), collect
the event stream and compute five evidence families:

**A. Structural / content**
- `H̄` mean entropy, `σ_H` std, `slope_H` OLS slope of entropy over time, `maxΔH`
- `H_section_skew` = `H_end − H_start` (partial-encryption signal — already implemented, keep)
- `format_valid` ∈ {0,1} — does content still parse as the claimed format? (ZIP central
  directory, JPEG SOI/EOI, PDF `%%EOF`, PNG IHDR/IEND, OLE compound file)
- `write_amplification` = bytes_written / bytes_original (≈1.0 for in-place encryption; ≫1 for
  editors; ≪1 for truncation)
- `magic_ext_mismatch` ∈ {0,1}

**B. Temporal**
- `rate` ops/s; `burstiness` = Fano factor or CV² of inter-event times (ransomware is
  *metronomic*; humans are bursty-then-idle)
- `regularity` = 1 − normalised entropy of inter-event-time distribution
- `session_duration`, `active_span`

**C. Sequential / access-pattern**
- `seq_score` = fraction of events consistent with a sorted directory walk (ransomware traverses
  deterministically; humans jump around)
- `dir_breadth` distinct directories touched; `dir_depth`; `scope_ratio` = breadth / estate size
- `read_write_ratio` (ransomware: read once, write once ≈ 1.0; editors: many reads per write)

**D. Transition / population**
- Extension transition matrix `T[e_src → e_dst]`, compared against a per-directory **baseline**
  transition model (χ² or KL divergence) — *no hardcoded family list*
- File-type distribution drift vs the directory's resting distribution
- `distinct_extensions_touched`, `novel_extension_ratio`

**E. Process / provenance**
- `process_age_sec` (**emitted on both attribution paths** — fixes F7)
- `parent_is_shell_or_office`, `ancestry_depth`, `process_io_bytes`, `attribution_confidence`
- `files_affected_by_this_pid` (from the campaign tracker — a real, available number)

**Symbolisation.** Quantise each scalar with **fixed, published cut-points** (e.g. `slope_H` →
{falling, flat, rising, steep-rising}) into a 3-5 symbol alphabet. Emit an ordered token stream
per session:

```
S = ⟨ H:steep σ:hi fmt:invalid wamp:1.0 rate:hi burst:metronomic seq:sorted
      breadth:wide rw:1.0 ext:docx→unknown pid:young io:hi ⟩
```

**Fingerprint.** Take the set of *k*-shingles of `S` (k=3) plus the top-*m* transition edges of
`T`, and compute a **64-bit SimHash**. Similar behaviour → small Hamming distance. Store
`(simhash, evidence_vector, first_seen, sources[], confidence)`.

**Matching.** Hamming distance `d`: `d ≤ 3` = same behavioural family (near-duplicate);
`4 ≤ d ≤ 10` = related (corroborating); `d > 10` = unrelated. Use a permuted-table / band
index for O(1) near-neighbour lookup instead of a full scan.

**Why this is defensible and novel *for this project*.** The decisive property — which I can
demonstrate empirically and which the current design provably lacks — is:

> **A behavioural SimHash is invariant to per-victim ciphertext randomisation; a content hash is
> not.**

I have already measured the negative half (1000/1000 distinct content hashes for one file). The
positive half is a straightforward experiment: run the same family against two hosts with
*independently randomised* payloads and show the behavioural SimHash distance stays ≤ 3 while the
content-hash distance is maximal. **That contrast is a publishable, demonstrable result, and it
is the honest core of the thesis.** It also makes the project title true.

*Intellectual honesty:* SimHash/MinHash locality-sensitive hashing is not new (Charikar 2002;
Broder 1997), and behavioural ransomware fingerprinting has prior art. Our contribution is not
the invention of SimHash. It is (a) the specific evidence-family schema above, tuned for
user-space filesystem telemetry on a commodity host, (b) the demonstration that it repairs a
concrete, measured failure of content-hash-based threat sharing, and (c) the integration with
explainable risk scoring, containment and a tamper-evident ledger. Phase 4 (blocked on your
papers) must confirm (a) and (b) against the actual literature before we claim novelty. **I will
not assert novelty until I have read the base papers.**

## 6.3 Risk scoring

Two-stage, auditable:

1. **Deterministic rule floor** (keep the existing one — it is the 0-false-quarantine guarantee
   and it is explainable by inspection).
2. **Weighted evidence aggregation** with explicit, published weights and per-family
   contribution caps, so no single family can drive a quarantine alone:

   `R = Σ_families min(w_f · s_f, cap_f)`, normalised to 0-100, with `cap_f` ≈ 35 for content,
   25 for temporal, 20 for sequential, 20 for transition, 25 for process/provenance, and
   **canary write = 100 by policy**.

3. **Calibrated ML on top** (RF, once F7 is fixed) — used to *rank* and to produce SHAP
   explanations, never to override the rule floor downward, and never to quarantine unless the
   deterministic evidence families independently agree. Keep the existing, correct invariant:
   *"Hard-confirmation signals are applied BEFORE any learned engine, so no model can ever talk
   the pipeline out of a confirmed incident."*

**Explainability output** (your §13 format), generated from the real evidence vector:

```
RISK 92/100 — QUARANTINE + TERMINATE
 + entropy slope steep-rising (H 4.9 → 7.8 in 1.2 s)          [content   +30]
 + format invalid: .docx no longer parses as ZIP container     [structural +35]
 + 147 files modified in 9.4 s, write amplification 1.02       [temporal  +25]
 + metronomic inter-event timing (CV² = 0.03)                  [temporal  +18]
 + sorted directory traversal, breadth 6/6 dirs                [sequential +16]
 + extension transition .docx→.unknown absent from baseline    [transition +20]
 + process age 2.1 s, parent=bash, no prior file history       [process   +22]
 ≈ behavioural fingerprint matches incident #14 (Hamming d=2)  [intel     +25]
```

Every line must be traceable to a measured value. No defaults, no constants (F3).

## 6.4 New components to add

- **Canary/honey files** — planted decoys across the estate, invisible to legitimate workloads,
  with format-valid content. Any open-for-write is a near-certain incident. Cheap, and it
  directly serves objective #12 (*protect unaffected files*) **pre-emptively** rather than
  post-hoc. Highest demo value per line of code in the whole plan: an examiner can watch the
  canary fire *before* a single real file is touched.
- **Format validator** — magic-byte and structural parse per extension. Closes `image_blindspot`
  orthogonally to entropy (F11).
- **Process monitor** — a real polling loop building a process tree snapshot with ancestry,
  creation time, cumulative I/O counters and per-PID touched-file sets. Serves objective #6 and
  fixes `process_age_sec`/`files_affected` (F7) and attribution confidence (F12).
- **Baseline modeller** — per-directory resting distributions (extension histogram, transition
  matrix, entropy histogram) learned during a quiet period, persisted, and versioned. Everything
  "anomalous" is measured against *this*, not against a hand-written constant table (F10).
- **Hash-chained audit ledger** — see F5.
- **Response policy engine** — declarative policy file (protected processes, per-risk-level
  actions, dry-run, safe-mode, confirmation-required actions, rollback enablement).

## 6.5 Response pipeline (your §9), with the safety controls you specified

```
detection → risk score + evidence vector
  → policy lookup (risk band × attribution confidence × protected-list check)
  → [DRY-RUN?] log intended action, touch nothing
  → [CONFIRMATION REQUIRED?] hold in pending queue, surface on dashboard, await operator
  → identify responsible process (only if identity_verified OR canary-triggered)
  → containment: suspend before terminate (preserves memory evidence), then terminate
  → quarantine file (verify: regular file, not symlink, inside watched estate)
  → restore from verified clean baseline (SHA-256 check before use) — already correct, keep
  → rename-back — already correct, keep
  → post-kill verification sweep — already correct, keep
  → forensic report (observed values only, never edited — fixes F12)
  → append to hash-chained ledger + anchor Merkle root
  → publish behavioural fingerprint to exchange
  → rollback token recorded so containment can be undone
```

Most of this already exists and is good. The additions are: **suspend-before-terminate**,
**declarative policy**, **pending-confirmation queue**, **rollback tokens**, and the
**never-edit-observed-values** rule.

---

# PHASE 8 — TECHNOLOGY SELECTION JUSTIFICATION

| Technology | Decision | Purpose → Implementation → Test → Result → Justification |
|---|---|---|
| Python 3.11 | **KEEP** | Whole system; reproducible; adequate performance for a file-telemetry agent |
| `watchdog` | **KEEP** | Cross-platform FS events → polling observer 0.2 s → tested live → works. Justified: standard, portable |
| `psutil` | **KEEP** | Process tree, I/O counters, open files, termination → already used → extend to a real monitor |
| Flask + flask-socketio (`threading`) | **KEEP** | Dashboard + sub-second push → verified working → adequate for a single-node lab |
| SQLite | **KEEP** | Event store, exchange, ledger → works, zero-config, reproducible |
| scikit-learn + SHAP | **KEEP** | RF ranking + per-incident explanation → real weights exist → **fix features first (F7)** |
| Hash-chained + HMAC + Merkle ledger | **ADD** | Tamper-evident audit that runs offline → new module → byte-flip test → demonstrable immutability. Justified: makes the project title true *and* reproducible without external infra |
| Ethereum/Ganache + web3 | **DEMOTE to optional** | External anchor for Merkle roots → keep `ThreatLogger.sol`, add `anchorRoot(bytes32)` → optional integration test. Justification for demotion: absent at every demo so far, `onlyOwner` gives no real multi-party verification, on-chain strings leak paths and cost gas |
| Canary/honey files | **ADD** | Pre-emptive protection + near-certain signal → new module → canary-scenario tests → highest demo value. Justified: cheap, orthogonal to entropy, serves objective #12 |
| Format validator | **ADD** | Closes `image_blindspot` → new module → blind-spot re-test. Justified: the only signal that defeats entropy-masking evasion |
| **PyTorch / DQN** | **REMOVE** | 711 lines, **no weights in repo**, never default, logs "unavailable" on every start, ~2 GB dependency. Purpose: none demonstrated. **Explicitly recommended for removal** per your §18 |
| **eventlet** | **REMOVE** | Unused (`async_mode="threading"`), deprecated upstream, prints a warning in every log |
| **`/api/telemetry` + `_relay_telemetry`** | **REMOVE** | Fabrication vector (F2). No legitimate purpose |
| **`_simulate_network_exploit`** | **REMOVE** | Scripted fiction + the direct cause of the deadlock (F1, F2c) |
| **`entropy_system.py`, `blockchain/blockchain_logger.py`** | **REMOVE** | Deprecation facades in a one-commit repo with no external callers |
| **root `test_blockchain.py`, `reset_test.py`** | **MERGE into `tests/`** | Currently never executed by `discover -s tests` |
| Kubernetes | **DO NOT ADD** | No multi-node orchestration need; would destroy reproducibility for a VTU demo |
| Federated learning | **DO NOT ADD** | No model is trained across nodes; the exchange shares fingerprints, not gradients |
| Reinforcement learning | **DO NOT ADD** | DQN removal above. An RL agent that takes destructive actions on a live filesystem is an unacceptable safety risk for a student demo and cannot be validated |
| eBPF | **DO NOT ADD** | Would genuinely improve Linux process attribution — but it is non-portable to Windows (the project's stated target, given `WHITELISTED_PROCESSES` and the `vssadmin` signatures), needs root + kernel headers, and cannot be demonstrated on an examiner's laptop. Replace with measured `psutil` polling **plus an explicit `attribution_confidence` field**, and publish the platform limitation |
| Post-quantum crypto / IPFS / sharding / multi-language | **DO NOT ADD** | No threat model or scale requirement justifies any of them |

---

# PHASE 9 — TESTING STRATEGY

1. **Fix isolation first** (otherwise every new test is unreliable): remove import-time
   `os.makedirs`; inject `DB_PATH`, `QUARANTINE_DIR`, `BACKUP_DIR`, `REPORTS_DIR` per test;
   one `tmpdir` per test; add `conftest`-style guards that fail loudly on shared-state writes.
2. **Correct the existing failures** — 5 real bugs (F3 ×2, F6 ×2, stale config ×1). Do not
   delete or `skip` them; they are good tests.
3. **Real-file corpus** (F10): genuine JPEG/PNG/MP4/ZIP/7z/TAR.GZ/PDF/DOCX/XLSX/SQLite, built
   with real encoders. Re-derive `NORMAL_ENTROPY_RANGES` empirically from it and publish the
   distribution.
4. **Scenario battery** — your §14 list, all as deterministic, seeded, reproducible scenarios:
   normal edit, copy, backup, ZIP creation, large-file processing, encryption-like write, rapid
   bulk modify, slow bulk modify, rename-heavy, high-entropy creation, **entropy-masking /
   entropy-sharing evasion**, unknown behavioural pattern, **canary-aware attacker**,
   **partial encryption**, **extension-preserving in-place encryption**, **rename-before-encrypt**,
   **intermittent low-and-slow**, **legitimate-process mimicry**.
5. **Adversarial loop** (your §15): for each bypass — explain *why* it bypassed, classify
   (real research gap vs. implementation defect vs. acceptable limitation), fix, re-test, record.
   Publish the whole loop, including the ones we do **not** fix. This is worth more marks than a
   clean sweep, because it is the actual scientific method.
6. **Failure injection** (your §23): kill detector → dashboard must show OFFLINE within
   `PIPELINE_STALE_SECONDS`; kill dashboard → pipeline must keep detecting and buffering;
   corrupt the ledger → `verify()` must report the exact entry; DB locked; disk full; permissions
   denied; 10 000-file burst → measure queue depth and drop count (backpressure already exists —
   assert it); network absent → exchange must degrade to local-only.
7. **Security tests** (your §21): vault requires PIN; SOC API requires token; `/api/telemetry`
   gone (assert 404); CORS restricted; symlink-out-of-estate quarantine refused; filename with
   newline/ANSI/HTML is sanitised in logs and escaped in the DOM; path-traversal on
   `/api/reports/<name>` refused; `grep` test asserting **no magic-constant defaults in the API
   layer** (mechanically prevents F3 recurring).
8. **Schema-contract test** (F7): build a feature vector from a real pipeline event and assert
   every feature is populated from a real producer — no defaults. This single test would have
   caught the entire skew.

# PHASE 10 — BENCHMARKING STRATEGY

**Keep and extend `benchmark/runner.py`** — it is the best-engineered part of the project. It
already drives the real `EntropyAnalyzer` + real `DecisionEngine` over deterministic scenarios
with a simulated clock and an isolated exchange, and it regenerates its own report. Verified:
reproduces 42/48 (87.5%), 0 false quarantines, RF 48/48 with 6 FQ — **exactly** as documented.

**Add:**

- **Baselines** (objective #21, currently absent), all on the identical corpus and scenarios:
  - **A — Entropy-only:** `H ≥ τ` → alert/quarantine. (Isolates the value of everything else.)
  - **B — Hash + entropy:** integrity-change detection plus entropy threshold.
  - **C — Behaviour-only:** temporal + sequential + transition, **no entropy at all**. (Proves
    entropy is not load-bearing on its own — and shows what it contributes.)
  - **D — Proposed:** full multi-layer + behavioural fingerprint + risk scoring.
  Report as your requested table: Accuracy / Precision / Recall / F1 / FPR / detection latency
  (wall-clock **and** ops) / % files affected before detection / false quarantines.
- **Wall-clock latency:** event timestamp → decision timestamp → containment timestamp →
  response-complete timestamp. Currently only "ops to detection" exists.
- **% estate affected before detection:** `files_modified_before_containment / total_estate`.
- **Resource overhead:** `psutil.Process.cpu_percent()`, `memory_info().rss`, `/proc/<pid>/io`
  read/write bytes, for idle / normal workload / heavy legitimate workload / attack — your §22
  matrix. **Nothing like this exists today.**
- **Fingerprint generalisation experiment:** same family, two hosts, **independently randomised**
  ciphertext → measure behavioural SimHash Hamming distance vs content-hash distance. This is
  the experiment that justifies the whole redesign, and it is the honest replacement for
  `exchange_simulation.py`'s fixed-seed artifact (F4).
- **Every number regenerated by script**, generator + artifact committed, and the report
  timestamped — the existing pattern, which is correct.

# PHASE 11 — THREAT MODEL OF OUR OWN SYSTEM (STRIDE)

| STRIDE | Threat to our system | Current exposure | Mitigation |
|---|---|---|---|
| **S**poofing | Attacker process renames itself to a whitelisted name (`explorer.exe`) to escape attribution and termination | **HIGH** — `WHITELISTED_PROCESSES` is name-based; `execute_response` even rewrites such names to `"ransomware_simulator"` | Attribute by PID + `create_time` + cmdline + ancestry, never by name alone; treat name-in-whitelist-with-mismatched-ancestry as *more* suspicious |
| | Unauthenticated caller posts to `/api/telemetry` and injects fake incidents | **CRITICAL** — exists today | Delete endpoint; token-auth all APIs |
| | Vault accessible with no PIN | **HIGH** — `return True` | Restore `compare_digest` + session expiry |
| **T**ampering | Adversary edits the SQLite ledger to erase an incident | **CRITICAL** — no chain, undetectable | Hash chain + HMAC + Merkle + `verify()`; alert on verification failure |
| | Adversary deletes `backup_storage/` to destroy recovery | ✅ **DETECTED** — `defense_guard` protected-path deletion → hard confirmation. Good design | Keep; extend to canary integrity |
| | Adversary poisons the fingerprint exchange so clean files get quarantined everywhere | ⚠️ mitigated — `EXCHANGE_CONFIRM_THRESHOLD ≥ 2` independent nodes; single sighting only corroborates (+25). Sound design | Keep; add per-node reputation and revocation |
| | Symlink inside the estate pointing at `/etc/passwd`, quarantined (moved) by the defender | **MEDIUM** — not verified | `realpath` containment + refuse non-regular files |
| **R**epudiation | Defender's own actions not attributable / observed values overwritten (F12) | **MEDIUM** | Never mutate observed values; record `requested` vs `actual` (schema already has both — use them) |
| **I**nformation disclosure | Quarantine vault exposes ciphertext + metadata to anyone | **HIGH** | Auth + read-only + access log |
| | On-chain `filePath` leaks internal directory structure and usernames | **MEDIUM** | Hash paths, or store only a path digest on-chain with the plaintext off-chain |
| | Filenames/cmdlines rendered unsanitised → log forging, DOM injection | **MEDIUM** | Sanitise on write, escape on render |
| **D**enial service | Attacker console deadlocks permanently → whole lab unusable | **CRITICAL** — F1, live | `RLock` + remove theatre from the lock path; add a watchdog that restarts a hung service |
| | 10 000-file burst floods the queue | ⚠️ mitigated — unbounded `Queue` with observable backpressure and a `dropped_count`; deliberately does not silently evict | Bound it, measure it, report drops on the dashboard |
| | Monitor's own CPU/IO starves the host | **UNKNOWN** — never measured | Phase 10 resource benchmarks; add a self-throttle |
| **E**levation of privilege | Defender terminates an innocent process because attribution guessed wrong | ⚠️ mitigated — refuses unverified attribution (held correctly in my live test, where it guessed `timeout`) | Persist `attribution_confidence`; suspend-before-terminate; confirmation for high-risk |
| | Defender runs as root and its quarantine directory becomes an attacker-writeable path back into the system | **MEDIUM** | Drop privileges; `0700` stores; verify ownership |

---

# PHASE 12 — IMPLEMENTATION ROADMAP

Sequenced so that **the demo works at every stage** and each stage produces measurable evidence.

**Stage 0 — Resuscitate (≈1 day). Makes the existing project demonstrable again.**
1. `_proc_lock = threading.RLock()`; move `_simulate_network_exploit` out of the lock — then
   delete it (F1).
2. Delete `/api/telemetry`, `_relay_telemetry`, both call sites (F2).
3. Fix `pipeline_status()`: real `online`, real `engine`, real `dry_run`, use
   `PIPELINE_STALE_SECONDS` (F6).
4. Remove all 19 fabrication defaults; return `null`; render `NOT RECORDED` (F3).
5. Restore vault auth (F3).
6. Add `terminate_result` / `quarantine_result` / `attribution_source` / `identity_verified`
   columns; stop rewriting whitelisted procnames (F3, F12).
7. Fix `requirements-ci.txt`; correct the README badge to the true count; update the stale config
   test (F7, F8).
8. **Gate:** `python lab.py` → click Launch → real kill, real quarantine, real restore, honest
   dashboard, no fabricated field. Full suite green.

**Stage 1 — Make the evaluation honest (≈3-4 days).**
9. Real-file corpus; re-derive entropy ranges empirically; replace `i % 128` fixtures (F10).
10. Emit the 6 missing ML features from the pipeline; rename `is_signed`; delete
    `is_known_process`; add the schema-contract test; retrain (F7).
11. Baselines A/B/C + wall-clock latency + % estate affected + resource overhead (Phase 10).
12. Remove DQN/torch, eventlet, deprecation facades, root-level strays (F14).
13. **Gate:** baseline comparison table exists and is regenerable; RF numbers are trustworthy.

**Stage 2 — Build the namesake (≈1-2 weeks). The research contribution.**
14. Process monitor: tree, ancestry, I/O counters, per-PID touched-file sets, attribution
    confidence (objective #6, F12).
15. Baseline modeller: per-directory resting distributions, persisted and versioned.
16. Format validator (F11).
17. Canary/honey files (objective #12).
18. **Behavioural fingerprint**: evidence families → quantisation → shingles → SimHash →
    Hamming lookup (Phase 6.2).
19. Weighted, capped, explainable risk scoring; keep the rule floor (Phase 6.3).
20. **Gate:** `image_blindspot` detected without entropy; canary fires before the first real file
    is touched; explanation output matches your §13 format with every value traceable.

**Stage 3 — Make the title true (≈1 week).**
21. Hash-chained + HMAC + Merkle ledger with `verify()`; Ethereum demoted to optional root
    anchor (F5).
22. Re-key the exchange on behavioural fingerprints; rewrite `exchange_simulation.py` to use
    **independently randomised** payloads per tenant (F4).
23. Two-node Host A → Host B demonstration (objective #14).
24. **Gate:** byte-flip the ledger on stage → `CHAIN BROKEN AT ENTRY n`; Host B detects a
    first-sight attack earlier using Host A's behavioural fingerprint, with different ciphertext.

**Stage 4 — Prove it under attack and under failure (≈1 week).**
25. Adversarial battery + the documented fix/re-test loop (Phase 9.5).
26. Failure injection (Phase 9.6) and security tests (Phase 9.7).
27. Threat model written up (Phase 11).
28. **Gate:** every bypass documented with a classification; every failure mode fails safe.

**Stage 5 — Package (≈3-4 days).**
29. README rewrite: one project name, honest badges, exact commands, troubleshooting that matches
    reality, known limitations.
30. Architecture diagram regenerated from the actual runtime.
31. Reproducibility: clean-clone script, `make demo`, `make test`, `make benchmark`, pinned and
    verified dependencies.
32. Demo script with a timed run-of-show and a **failure-recovery rehearsal** (what to do if the
    live demo breaks in front of the examiner).
33. Thesis chapters mapped to evidence: every claim cites a regenerable artifact.

---

## FINAL QUALITY GATE — STATUS: **FAILED**

```
FAILED QUALITY GATE

1. Problem: Documented demo deadlocks permanently on first attack launch.
   Root cause: attacker_server/app.py:47 _proc_lock is a non-reentrant threading.Lock;
               _spawn() holds it while _append_log() re-acquires it (via
               _simulate_network_exploit). Proven by captured stack trace.
   Required fix: RLock + remove the theatre function from the lock path (then delete it).
   Test required: end-to-end launch test asserting /api/launch returns 200 and the engine
                  starts; concurrency test that /api/stats stays responsive during a launch.
   Expected evidence: lab.py → Launch → real kill + quarantine + restore; suite green.

2. Problem: Fabricated detection events, forensic evidence and dashboard counters.
   Root cause: /api/telemetry (attacker-authored, unauthenticated, destructive) plus 19
               hardcoded "success" defaults in app.py and victim_server/app.py; underlying
               schema gap — terminate_result is never persisted.
   Required fix: delete the injection path; persist real outcomes; return null, never constants.
   Test required: grep-test forbidding magic constants in the API layer; test that a refused
                  termination renders as NOT KILLED; test that /api/telemetry is 404.
   Expected evidence: dashboard values byte-identical to DB rows; no field unbacked by data.

3. Problem: Behavioural fingerprint does not exist; threat-intel exchange cannot match.
   Root cause: fingerprint = SHA-256 of ciphertext; os.urandom payload ⇒ 1000/1000 distinct
               hashes for one file; exchange benchmark passes only because it feeds every
               tenant byte-identical fixed-seed payloads.
   Required fix: behavioural SimHash fingerprint; re-key the exchange; randomise per tenant.
   Test required: two-host test with independently randomised ciphertext asserting small
                  behavioural Hamming distance and maximal content-hash distance.
   Expected evidence: Host B detects a first-sight attack earlier using Host A's fingerprint.

4. Problem: No immutability — the project's namesake component is a plain SQLite table.
   Root cause: LocalLedger has no prev_hash, Merkle root, signature or verify().
   Required fix: hash-chained + HMAC + Merkle-anchored ledger with verify(); Ethereum optional.
   Test required: tamper test — flip one byte, assert verify() names the exact broken entry.
   Expected evidence: on-stage byte-flip → "CHAIN BROKEN AT ENTRY n".

5. Problem: Fail-open health reporting.
   Root cause: pipeline_status() hardcodes online=True in both branches;
               PIPELINE_STALE_SECONDS defined and never used. Two tests fail.
   Required fix: derive online from heartbeat age; report real engine/dry_run/pid.
   Test required: the two existing failing tests, plus a kill-the-detector integration test.
   Expected evidence: dashboard shows OFFLINE within 8 s of the detector dying.

6. Problem: ML train/serve skew — 6 of 11 RF features have no producer.
   Root cause: features defined only in ai/; age_seconds set only on the unverified attribution
               path; is_signed misnamed; is_known_process a literal duplicate.
   Required fix: emit features from the pipeline; rename; deduplicate; retrain.
   Test required: schema-contract test asserting every feature comes from a real producer.
   Expected evidence: feature distribution at inference matches training; no default values.

7. Problem: Reproduction instructions do not work; test/badge claims false.
   Root cause: requirements-ci.txt omits scikit-learn (a hard test dependency); README claims
               "126 tests, 0 fail" vs actual 145 tests, 5 failing; config.py performs
               import-time os.makedirs causing test-order pollution.
   Required fix: correct CI deps; lazy directory creation; update stale test; honest badge.
   Test required: clean-venv install of requirements-ci.txt then full suite.
   Expected evidence: green suite from a clean clone, with an accurate published count.

8. Problem: No baselines, no wall-clock latency, no resource-overhead measurement,
            no adversarial battery, no failure injection, no threat model.
   Root cause: objectives #19, #21 and brief §15, §21, §22, §23 were never implemented.
   Required fix: Phases 9, 10, 11 and roadmap stages 1, 4.
   Test required: regenerable benchmark producing the full comparison table.
   Expected evidence: A/B/C/D comparison with latency, FPR, % estate affected, CPU/RAM/IO.
```

---

## WHAT I NEED FROM YOU TO CONTINUE

1. **The research materials.** Your brief lists a major-project report, Phase-I report, synopsis,
   literature review, base papers and architecture diagrams. **None are in the repository** — and
   there is not a single citation anywhere in the codebase. I cannot write Phase 4 (base-paper
   comparison) or validate the research gap against the literature without them, and I will not
   invent citations. In particular I need the paper you mention on **entropy-sharing techniques
   that bypass entropy-based detection** — it is central to the redesign in Phase 6.
2. **Confirmation of the demo platform.** `WHITELISTED_PROCESSES` and
   `TAMPER_CMDLINE_SIGNATURES` are Windows-specific (`svchost.exe`, `vssadmin`, `wbadmin`), but
   the lab runs on Linux. Which platform will you demonstrate on? This decides whether the
   process-monitoring layer targets Windows ETW/`psutil` or Linux `/proc`/`psutil`.
3. **Approval to remove** PyTorch/DQN (~711 lines, no weights), eventlet, and the deprecation
   facades — per your §18, I recommend removing all three.
