# EntropYY — New Research Direction & Redesigned Architecture

**Supersedes:** Phase-I architecture (treated as academic baseline only, per instruction)
**Status:** PROPOSAL — awaiting approval. No code written.
**Date:** 2026-10-04
**Companion:** `docs/audit/AUDIT-PHASE1-12.md` (empirical audit of the existing repository)

---

## 0. HOW THIS DOCUMENT WAS PRODUCED

A fresh literature review was performed (6 searches, ~60 sources screened, 20 used). Every
technical decision below cites the work that motivates it. Where the literature shows that an
idea we might have claimed as novel **already exists**, that is stated plainly and the claim is
withdrawn.

**The single most important result of this review:** the field has moved on from our Phase-I
design, and several of our intended "innovations" are already published. This is good news — it
means we can build on verified results instead of reinventing them, and it forces us to find a
contribution that is actually defensible.

---

## 1. NEW RESEARCH DIRECTION

### 1.1 What the literature establishes as settled (we must NOT claim these)

| Established result | Source | Consequence for us |
|---|---|---|
| **Entropy-based detection is defeated.** "Entropy sharing" post-processes AES ciphertext into blocks at *benign* entropy levels, is lightweight, works with any cipher, and cannot be nullified without knowing the share order. Validated with NIST SP 800-22 frequency tests. | Bang, Kim & Lee, *Entropy Sharing in Ransomware: Bypassing Entropy-Based Detection of Cryptographic Operations*, **Sensors** 24(5):1446, 2024 — [mdpi.com/1424-8220/24/5/1446](https://www.mdpi.com/1424-8220/24/5/1446) | **This is the paper you referred to.** A whole-file entropy threshold is worthless against it. Our Phase-I core is obsolete. |
| Encoding-based neutralisation (Base64/ASCII85/Base32/URL) predates it | *Entropy* 22(2):239, 2022 — [mdpi.com/1099-4300/24/2/239](https://www.mdpi.com/1099-4300/24/2/239) | Same |
| Format-Preserving Encryption lets the attacker **choose** the ciphertext entropy by radix selection | *Sensors* 23(10):4728, 2023 — [mdpi.com/1424-8220/23/10/4728](https://www.mdpi.com/1424-8220/23/10/4728) | Entropy is attacker-controlled, not a physical constant |
| The inadequacy of entropy detection was already argued in 2019 | McIntosh et al., *The Inadequacy of Entropy-Based Ransomware Detection* — [researchgate.net/publication/337776801](https://www.researchgate.net/publication/337776801_The_Inadequacy_of_Entropy-Based_Ransomware_Detection) | Our Phase-I premise was already contested 5 years before |
| **Behavioural correlation for evasive ransomware exists.** ERW-Radar (NDSS 2025) detects evasive ransomware via long-term I/O *repetitiveness*, χ² correlation of local+global behaviour, dynamic window; 96.12% accuracy, 5.09% CPU / 3.80% memory overhead | [NDSS 2025 paper 230349](https://www.ndss-symposium.org/wp-content/uploads/2025-349-paper.pdf) | We **cannot** claim "behavioural correlation against evasive ransomware" as novel. We can adopt its insight. |
| **Canary/deception detection exists and is fast.** IRDS4C: 53 Windows samples, 7 families, ~12 s mean detection, "often quicker than file hashing or entropy analysis" | [IRDS4C–CTIB, Future Internet 18(1):66, 2026](https://doi.org/10.3390/fi18010066) | We cannot claim canaries as novel |
| **SimHash behavioural fingerprinting of malware exists.** MHAS converts opcode sequences to a **40-bit SimHash fingerprint** for family clustering | [PLOS ONE 14(8):e0211373](https://journals.plos.org/plosone/article?id=10.1371%2Fjournal.pone.0211373) | **We cannot claim "SimHash fingerprint for malware" as novel.** SimHash is Charikar 2002. |
| LSH/MinHash + banding for malware clustering at scale (1M samples, ~4 s, >99.9% recall) | [IEEE 6936960](https://ieeexplore.ieee.org/document/6936960/) | Established technique — adopt, don't claim |
| Similarity hashing (TLSH, ssdeep, IMPHash, Nilsimsa, SDHASH) for variant detection, with documented misuses and threshold-selection problems | Botacin et al. — [marcusbotacin.github.io](https://marcusbotacin.github.io/files/marcus_similarity_hashing.pdf); [arXiv 2512.09539](https://arxiv.org/html/2512.09539v1) | Adopt; heed the threshold-selection warning |
| **Blockchain CTI sharing exists** and is widely published | [CTI survey, J. Information Security & Applications](https://www.sciencedirect.com/science/article/pii/S2214212624000899); IRDS4C–CTIB above | We cannot claim "blockchain for threat intel" as novel |
| Segment-level entropy **classification** (not thresholding) beats HEDGE substantially: RF F1 0.95–1.00 vs HEDGE 0.59–0.94 | *Not on my watch*, **J. Cybersecurity** 11(1):tyaf009, 2025 — [academic.oup.com](https://academic.oup.com/cybersecurity/article/11/1/tyaf009/8109429) | Direct upgrade path for our entropy layer |
| ML detection of entropy-manipulated (FPE) ransomware: 94.64% average precision | *Sensors* 25(8):2406, 2025 — [mdpi.com/1424-8220/25/8/2406](https://www.mdpi.com/1424-8220/25/8/2406) | Confirms ML-on-content is the counter to entropy manipulation |

### 1.2 What the literature establishes as STILL OPEN (our opportunity)

| Open gap | Evidence |
|---|---|
| **G1 — Bang et al.'s own counter is impractical.** Their defence ("entropy recomposition") requires knowing the share order *m*. A defender does not. They further concede: *"Since this I/O pattern is not easy to be distinguishable from legitimate file operations (due to the benign level of entropy), checking I/O access patterns and entropy leads to a decrease in the true positive rate."* — i.e. **they admit that when entropy is masked, behavioural/I/O analysis also degrades.** | [Sensors 24(5):1446 §5.1, §5.4](https://www.mdpi.com/1424-8220/24/5/1446) |
| **G2 — Canary placement is not robust to traversal order.** *"witness tripwire files offer limited value as there is no way to influence the malware to access the area"*; attacks *"can be thwarted by reversing the order of files attacked, meaning any early detection files would be attacked last"*; *"a honeypot free from attack alerts is not an indicator that other areas are not being targeted."* | Moore, *Detecting Ransomware with Honeypot Techniques*, IEEE 2016 — [ieeexplore.ieee.org/document/7600214](https://ieeexplore.ieee.org/document/7600214/) |
| **G3 — Even kernel-level canaries cannot guarantee zero prior encryption.** *"it is hard to be certain on Windows systems that no file has been encrypted before the detection (and, if wanted, termination) occurs. This is not a product defect, it is due to the very structure of how MiniFilters work."* | Elastic Security Labs, *Ransomware in the honeypot: how we capture keys with sticky canary files* — [elastic.co](https://www.elastic.co/security-labs/ransomware-in-the-honeypot-how-we-capture-keys) |
| **G4 — Generalisation to VARIANTS is poor.** RanSMAP: mean recall on ransomware **variants** only **0.55 / 0.62 / 0.71** (storage+memory / storage / memory); 12-class recall **0.19**. | [RanSMAP, Computers & Security 2024](https://www.sciencedirect.com/science/article/pii/S0167404824005078) |
| **G5 — Evaluation is not reproducible.** *"almost no proposal provided enough detail on how the test data set was created, or sufficient description of its actual content, to allow it to be recreated by other researchers."* NapierOne was built specifically to fix this. | [Comprehensive performance benchmarking of active ransomware threats, Computers & Electrical Engineering 132:110963, 2026](https://www.sciencedirect.com/science/article/pii/S0045790626000315) |
| **G6 — Nobody optimises or reports DAMAGE BEFORE CONTAINMENT.** Encryption runs 33 MB/s → 2.79 GB/s; *"the rapidly shrinking window for detection and response."* Splunk SURGe: median total encryption ~43 min, fastest <6 min. Practitioner guidance: *"Set the target in files lost, then work backwards to seconds… Measure your pipeline end to end: telemetry ship time plus aggregation window plus inference plus response action."* | [same benchmark paper](https://www.sciencedirect.com/science/article/pii/S0045790626000315); [gtkcyber](https://gtkcyber.com/blog/detecting-ransomware-machine-learning/) |
| **G7 — Blockchain is on the wrong side of the latency budget.** A blockchain CTI framework *"peaks at just 0.32 messages per second"* vs sub-millisecond for DDS; of 11 blockchain CTI solutions studied, *"none addressed network bandwidth limitations, and only 27% attempted to improve timeliness"*; IRDS4C–CTIB stores ~220 kB/incident on-chain and itself recommends *"storing only cryptographic hash summaries on chain, with full reports maintained in off-chain storage."* | [Electronics 14(20):4045, 2025](https://doi.org/10.3390/electronics14204045); [CTI survey](https://www.sciencedirect.com/science/article/pii/S2214212624000899); [IRDS4C–CTIB](https://doi.org/10.3390/fi18010066) |
| **G8 — Defenders are killed first, routinely.** BYOVD terminating 300+ EDR drivers; ETW suppression; kernel-callback unregistration; Akira's PowerTool/Zemana driver abuse; SilentKill; EDRKillShifter; Snatch rebooting into Safe Mode. | [CISA via Lumu](https://lumu.io/blog/cisa-reveals-ransomware-gangs-bypassing-edrs/); [Vectra](https://www.vectra.ai/topics/ransomware-detection); [Recorded Future H1-2025](https://www.recordedfuture.com/research/h1-2025-malware-and-vulnerability-trends) |

### 1.3 THE NEW RESEARCH DIRECTION

> **Damage-Minimising Adaptive Defence (DMAD):**
> A continuously-running, user-space ransomware defence agent whose objective function is not
> *detection accuracy* but **bytes lost before containment** — built on evidence that survives
> entropy manipulation, and whose containment intelligence is shareable across hosts because it
> is keyed on a fingerprint that is **invariant to per-victim payload randomisation**.

Three pillars, each grounded in a documented open gap:

**Pillar 1 — Entropy-orthogonal structural evidence (answers G1).**
Bang et al. reduce Shannon entropy to *benign levels*, but they do not — and cannot — restore
**file-format structure**. Entropy sharing produces a byte mixture at benign entropy; it does not
produce a valid ZIP central directory, JPEG SOI/EOI/SOS marker sequence, PDF xref table, or PNG
IHDR…IEND chain. So we detect on **structural validity** and **byte-distribution χ² against the
file type's own benign distribution**, plus **segment-level entropy classification** (per
*Not on my watch*) rather than a whole-file threshold.

*Stated as a hypothesis, not a claim:* structural validity and χ²-against-type survive entropy
sharing. **We will test this by implementing entropy sharing as a safe simulator and measuring.**
If it fails, we report that honestly — Bang et al.'s §5.4 concession suggests it may partially
fail, and that result would itself be publishable.

**Pillar 2 — Order-robust deception + predictive pre-emptive protection (answers G2, G3, G6).**
Moore showed alphabetical canaries are defeated by reverse-order traversal; Elastic showed even
kernel canaries cannot guarantee zero prior encryption. Our answer is two-fold:
- **Order-robust canary layout**: canaries placed at *every* traversal-order attractor —
  alphabetically first, alphabetically last, random interior positions, and at least one per
  directory — with plausible names, sizes and access times. We then **measure detection order
  under forward / reverse / random / canary-skipping traversal**, which no prior work reports.
- **Predictive write-ahead snapshotting**: once risk crosses a *low* threshold, the agent infers
  the attacker's traversal order from observed accesses and **pre-emptively snapshots the files
  that order implies are next** — before they are touched. This is safe (read-only on user data,
  writes only to the backup store) and it attacks the metric nobody optimises: **files lost**.
  G3 says you cannot guarantee zero prior encryption; we do not claim to. We claim to
  **bound the loss**, and we measure the bound.

**Pillar 3 — Randomisation-invariant behavioural fingerprint for cross-host containment intel
(answers G4, and repairs a defect we measured in our own code).**
Our audit measured that the current content-hash fingerprint yields **1000/1000 distinct hashes
for one file** under `os.urandom` — so hash-based IOC sharing has *zero* cross-host collision
probability against any real ransomware. A behavioural fingerprint does not depend on payload
bytes at all.

**We do not claim SimHash as novel** (MHAS already uses it on opcode sequences; Charikar 2002).
Our contribution is narrower and honest:
- (a) applying LSH fingerprinting to **filesystem behavioural sessions** rather than binary or
  opcode content;
- (b) **empirically demonstrating the randomisation-invariance contrast** — behavioural Hamming
  distance stays small across hosts with independently randomised ciphertext, while content-hash
  distance is maximal;
- (c) using it as the key for **cross-host containment intelligence**, and measuring the
  improvement: *does Host B contain a first-sight attack faster than Host A did?*

### 1.4 Blockchain's role — deliberately narrowed (answers G7)

The literature is unambiguous that blockchain is too slow for a detection hot path (0.32 msg/s).
We therefore **remove it from the hot path entirely** and scope it to three operations where
immutability is genuinely load-bearing:

| Use | Justification | Cost |
|---|---|---|
| **1. Containment-decision provenance (anti-repudiation)** | A hash-chained local ledger proves *we contained at time T for reason R*, and makes post-incident tampering detectable. G8 shows defenders get killed — a tamper-evident record of what the agent did before it died has real forensic value | Local, ~µs/entry |
| **2. Behavioural-fingerprint publication integrity** | Host B must be able to verify that intel it received from Host A was not altered or forged. On-chain: a 32-byte digest. Off-chain: the payload. Exactly what IRDS4C–CTIB recommends as future work | 32 bytes per anchor |
| **3. Response-policy integrity** | Anchor a hash of the active response policy, so a policy tampered with by an attacker (e.g. to disable termination) is detectable | 32 bytes on policy change |

**Implementation:** primary = local append-only ledger with
`entry_hash = SHA256(prev_hash ‖ canonical_json(payload))` + `tag = HMAC(node_key, entry_hash)`
+ Merkle root every *N* entries + `verify()` that reports the first divergence.
External chain (Ganache/geth) = **optional** anchor for Merkle roots only.

This makes the word "Blockchain" in the title **true and defensible** while removing it from
anywhere it would hurt. If the evaluator asks "why blockchain?", the answer is a measured
tamper-detection demonstration, not a buzzword.

---

## 2. NEW END-TO-END ARCHITECTURE

### 2.1 Design rules

1. **Three separated layers** — DETECTION, DECISION, RESPONSE — as distinct subsystems with
   explicit contracts. Never one function.
2. **No signal is a hard gate.** (Our audit found entropy is currently a hard precondition in
   `CampaignTracker._qualifies` — that is the single worst design defect.)
3. **Nothing on the hot path waits for I/O we don't control** (no chain, no network).
4. **Every number rendered anywhere is backed by a persisted measurement, or is `null`.**
5. **Fail safe, not open.** A dead detector must be *visible*.
6. **Every layer degrades independently** — losing one evidence family reduces confidence
   gracefully; it does not collapse detection.

### 2.2 Architecture

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║  ENTROPYY DEFENCE AGENT  —  continuously running, user-space, per-host           ║
╚══════════════════════════════════════════════════════════════════════════════════╝

┌── CONTROL PLANE ────────────────────────────────────────────────────────────────┐
│  protection policy (declarative file, hash-anchored)                             │
│    • protected directories        • canary layout policy                         │
│    • response authority per risk band   • protected process list                 │
│    • dry_run | safe_mode | confirmation_required | rollback_enabled              │
│  agent supervisor: liveness heartbeat → ledger; self-integrity; restart          │
└──────────────────────────────────┬───────────────────────────────────────────────┘
                                   │
┌── SENSING ───────────────────────▼───────────────────────────────────────────────┐
│  S1 filesystem watcher (recursive, bounded queue, measured backpressure)         │
│  S2 canary grid (order-robust layout: first/last/interior/per-directory)         │
│  S3 process monitor (tree, ancestry, create_time, cumulative I/O, cmdline)       │
│  S4 baseline modeller (per-directory resting distributions, learned + versioned) │
│  S5 recovery-capability monitor (backup/shadow/service tampering — T1490)        │
└──────────────────────────────────┬───────────────────────────────────────────────┘
                                   │  normalised event stream (typed, attributed)
                                   ▼
╔═══ LAYER 1: DETECTION — "is this behaviour suspicious?" ═════════════════════════╗
║  SESSION AGGREGATOR                                                              ║
║    write session = (attributed process ∥ process-group, directory subtree,       ║
║                     sliding window 30–60 s)  +  long-horizon view (minutes)      ║
║    ⟶ per-session evidence vector, aggregated (NOT per-event scoring)             ║
║                                                                                  ║
║  F1 STRUCTURAL  (entropy-orthogonal — Pillar 1)                                  ║
║     format validity (ZIP/JPEG/PDF/PNG/OLE/MP4 structural parse)                  ║
║     magic ↔ extension agreement                                                  ║
║     segment-level entropy profile → trained classifier (not a threshold)         ║
║     byte-distribution χ² vs the file type's own benign distribution              ║
║     write amplification · read:write ratio                                       ║
║  F2 TEMPORAL                                                                     ║
║     rate · burstiness (Fano factor, CV²) · inter-arrival regularity              ║
║     ★ long-horizon self-similarity: χ² correlation of behaviour SEGMENTS         ║
║       (ERW-Radar's "unique repetitiveness" — the low-and-slow counter)           ║
║  F3 TOPOLOGICAL / SCOPE                                                          ║
║     ★ directory breadth (distinct dirs written per window)                       ║
║     extension churn · rename rate · novel-extension ratio                        ║
║     traversal-order score (sorted-walk correlation, forward/reverse/random)      ║
║     file-type distribution drift vs baseline (KL)                                ║
║  F4 PROCESS / PROVENANCE                                                         ║
║     parent–child anomaly · ancestry depth · process age at first write           ║
║     first-sight binary on this host · recovery-capability tampering              ║
║     ★ ATTRIBUTION CONFIDENCE (gates response authority)                          ║
║  F5 DECEPTION                                                                    ║
║     canary open-for-write / modify / rename (near-certain, order-robust)         ║
║  F6 INTELLIGENCE                                                                 ║
║     behavioural fingerprint Hamming match (corroborating, capped, ≥2 nodes)      ║
║                                                                                  ║
║  OUTPUT: {family scores s_f, raw measured signals, session id}                   ║
╚══════════════════════════════╤═══════════════════════════════════════════════════╝
                               │  (no action authority in this layer)
                               ▼
╔═══ LAYER 2: DECISION — "how confident are we, and what does that authorise?" ════╗
║  1. per-family calibration → p_f ∈ [0,1]                                         ║
║  2. redundancy discount (correlated signals inside a family)                     ║
║  3. NOISY-OR fusion across families with per-family CAPS:                        ║
║         P = 1 − Π_f (1 − min(p_f, cap_f))                                        ║
║     ⟶ multiple weak independent signals accumulate; removing ONE family          ║
║       degrades gracefully instead of collapsing (this is the direct answer       ║
║        to "if entropy fails, do we still detect?")                               ║
║  4. isotonic calibration on held-out data → genuine probability                  ║
║     (report Brier score + reliability diagram)                                   ║
║  5. deterministic RULE FLOOR retained — ML may never lower it                    ║
║  6. hysteresis + dwell time (sustained evidence required for destructive action)  ║
║                                                                                  ║
║  ESCALATION LADDER      RISK BAND      RESPONSE AUTHORITY                        ║
║    NORMAL                P < 0.10      L0 observe                                ║
║    DEVIATION             0.10–0.35     L1 advise  + L2 predictive snapshot       ║
║    SUSPICIOUS            0.35–0.65     L2 restrict (write-ahead snapshot ON)     ║
║    HIGH-RISK             0.65–0.85     L3 contain (suspend + block writes)       ║
║    CONFIRMED             ≥ 0.85        L4 terminate + quarantine + restore       ║
║    canary hit            override →    L3 immediately, L4 if attribution verified║
║                                                                                  ║
║  DESTRUCTIVE ACTION REQUIRES:  P ≥ θ_high  AND  attribution_confidence ≥ θ_attr  ║
║                                AND  ≥2 families above their floor                ║
║  OUTPUT: {P, band, authority, per-family contributions, explanation, decision id}║
╚══════════════════════════════╤═══════════════════════════════════════════════════╝
                               │
                               ▼
╔═══ LAYER 3: RESPONSE — "what do we do RIGHT NOW?" ═══════════════════════════════╗
║  POLICY ENGINE → authority level → safety gates → action                         ║
║                                                                                  ║
║  L0 OBSERVE    log only                                                          ║
║  L1 ADVISE     dashboard warning; no filesystem action                           ║
║  ★L2 RESTRICT  PREDICTIVE WRITE-AHEAD SNAPSHOT (Pillar 2)                        ║
║                infer traversal order from observed accesses → snapshot the files ║
║                that order implies are NEXT, before they are touched.             ║
║                read-only on user data; writes only to backup store. SAFE.        ║
║                → directly minimises "files lost before containment"              ║
║  L3 CONTAIN    SUSPEND process (SIGSTOP — preserves memory for forensics, per    ║
║                Elastic's canary→memory-dump→key-recovery result)                 ║
║                + block further writes by that PID where the platform supports it ║
║                + snapshot in-flight file                                         ║
║  L4 TERMINATE  kill (VERIFIED identity only) → quarantine (regular-file +        ║
║                symlink checks) → restore SHA-256-verified clean copy →           ║
║                rename-back → campaign sweep → post-kill content verification     ║
║  L5 ISOLATE    revoke write access to the protected subtree for the session;     ║
║                operator confirmation required outside lab mode                   ║
║                                                                                  ║
║  SAFETY (non-negotiable): protected process list (file-based) · dry_run ·        ║
║    safe_mode · confirmation queue · rollback tokens · never act on unverified    ║
║    attribution except canary-triggered · never mutate observed values            ║
║                                                                                  ║
║  OUTPUT: {actions taken, actual outcomes, rollback token, evidence bundle}       ║
╚══════════════════════════════╤═══════════════════════════════════════════════════╝
                               │
             ┌─────────────────┼──────────────────────┬─────────────────────┐
             ▼                 ▼                      ▼                     ▼
   ┌──────────────────┐ ┌────────────────────┐ ┌───────────────────┐ ┌────────────────┐
   │ BEHAVIOURAL      │ │ TAMPER-EVIDENT     │ │ FORENSIC EVIDENCE │ │ SOC DASHBOARD  │
   │ FINGERPRINT      │ │ AUDIT LEDGER       │ │ BUNDLE            │ │ (token auth,   │
   │ quantise →       │ │ hash chain + HMAC  │ │ observed values   │ │  CORS locked,  │
   │ shingles →       │ │ + Merkle root/     │ │ ONLY, requested   │ │  null renders  │
   │ 64-bit SimHash → │ │   anchor           │ │ vs ACTUAL outcome │ │  as "NOT       │
   │ banded LSH index │ │ verify() →         │ │ attribution conf. │ │  RECORDED")    │
   │                  │ │  first divergence  │ │ rollback token    │ │ real-time push │
   │ Hamming d:       │ │                    │ │                   │ │ detection ∥    │
   │  ≤3 same family  │ │ OPTIONAL external  │ │                   │ │ red-team panel │
   │  4–10 related    │ │  anchor (32 B)     │ │                   │ │ SEPARATED      │
   │  >10 unrelated   │ │ policy-hash anchor │ │                   │ │                │
   └────────┬─────────┘ └────────────────────┘ └───────────────────┘ └────────────────┘
            ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ CROSS-HOST INTEL (off-chain payload, on-chain digest)        │
   │  Host A contains → publishes behavioural fingerprint         │
   │  Host B first-sight attack → Hamming d ≤ 3 → CONTAINS EARLIER│
   │  ≥2 independent nodes → confirmed; 1 node → corroborate only │
   │  (poison-node defence retained from existing design)         │
   └─────────────────────────────────────────────────────────────┘
```

### 2.3 Why noisy-OR and not a weighted sum

You told me not to accept your `Risk = entropy + temporal + file-op + process + fingerprint +
intel` formula blindly. I reject it, for a specific reason:

A **weighted sum** lets one family dominate, and lets an attacker **compensate**: suppress the
entropy term and the sum falls below threshold even if five other terms are elevated. That is
precisely how our current code fails (`if ent < ENTROPY_THRESHOLD: return False`).

**Noisy-OR**, `P = 1 − Π(1 − p_f)`, has the property we actually need:

- Several **weak independent** signals accumulate to high confidence.
- Ablating **one** family (exactly what an entropy-masking attacker does) degrades P
  **gracefully** rather than collapsing it to zero.
- It is directly **measurable**: run the whole battery with each family ablated and report the
  detection drop per family. That is a proper ablation study — strong thesis material, and it
  *proves* the answer to "if entropy fails, do we still detect?"

Caveats handled honestly: noisy-OR assumes independence, which is false (segment entropy and
byte-χ² correlate). So we (a) cluster correlated signals into families, (b) apply a redundancy
discount within families, (c) cap each family so none dominates, and (d) **isotonic-calibrate
the output** and report calibration error. If calibration is poor we say so.

---

## 3. THE THIRTEEN DELIVERABLES

### 3.1 Research gap

See §1.2 (G1–G8). Condensed:

> Existing detectors fail in a **correlated** way: entropy is attacker-controlled
> (Bang 2024; FPE 2023; Base64 2022), behavioural detection is evadable by I/O splitting and
> benign imitation (ERW-Radar's own motivation), canaries are defeated by traversal order
> (Moore 2016) and cannot guarantee zero prior loss (Elastic), variant generalisation is poor
> (RanSMAP recall 0.55–0.71), evaluation is not reproducible (benchmark paper), and **nobody
> optimises or reports damage-before-containment** despite encryption at up to 2.79 GB/s.
> Meanwhile hash-based IOC sharing is void against randomised ciphertext — which we measured in
> our own codebase (1000/1000 distinct hashes).

### 3.2 Novel contribution

Stated conservatively, with prior art explicitly excluded:

| Claim | Novel? | Prior art we acknowledge |
|---|---|---|
| SimHash / LSH fingerprinting | ❌ **NO** | Charikar 2002; MHAS (SimHash on opcode sequences); IEEE minhash+banding malware clustering |
| Canary/deception detection | ❌ **NO** | IRDS4C (~12 s); Elastic sticky canaries; Moore 2016 |
| Behavioural correlation vs evasive ransomware | ❌ **NO** | ERW-Radar, NDSS 2025 |
| Blockchain CTI sharing | ❌ **NO** | IRDS4C–CTIB; many others |
| Segment-level entropy classification | ❌ **NO** | *Not on my watch*, J. Cybersecurity 2025 |
| **C1 — Order-robust canary layout, with measured detection order under forward / reverse / random / canary-skipping traversal** | ✅ **Yes** — directly addresses Moore's documented, unaddressed limitation | Moore identified the problem; nobody in our review measured or solved it |
| **C2 — Predictive write-ahead snapshotting: infer traversal order and snapshot the *next* targets before they are touched, to bound damage** | ✅ **Yes** — reframes the objective from detection to *damage minimisation* (G6) | Elastic concedes zero-prior-loss is unachievable (G3); we bound it instead of claiming to prevent it |
| **C3 — Empirical demonstration that a filesystem-behavioural LSH fingerprint is invariant to per-victim payload randomisation where a content hash provably is not, used as the key for cross-host containment intel, with measured time-to-contain improvement on Host B** | ✅ **Yes (as an application + measurement)** | LSH is established; applying it to behavioural sessions and proving the invariance contrast is not, in the sources reviewed |
| **C4 — Noisy-OR multi-family fusion with per-family caps and published per-family ablation, explicitly engineered so that entropy-masking degrades rather than defeats detection** | ⚠️ **Partial** — fusion is standard; the *ablation-verified entropy-independence* of a working agent is the contribution | Weighted-sum and ML fusion are ubiquitous |
| **C5 — A reproducible damage-before-containment benchmark: files lost, bytes lost, decomposed end-to-end latency, over a published corpus and a published evasion battery** | ✅ **Yes (methodological)** | G5 and G6 — explicitly identified as missing |

**Headline contribution (one sentence):**

> A continuously-running user-space ransomware defence agent that treats **bytes-lost-before-
> containment** as its objective function, detects through evidence **orthogonal to entropy**
> (structural validity, byte-distribution χ², segment classification, long-horizon behavioural
> self-similarity), bounds damage through **order-robust canaries and predictive write-ahead
> snapshotting**, and shares containment intelligence across hosts through a behavioural
> fingerprint **provably invariant to payload randomisation** — anchored by a tamper-evident
> ledger scoped off the hot path.

**I will not call C1–C5 novel in the thesis until Phase 4 (base-paper comparison) is completed
against your actual supplied papers.** This review covers what I could find; your supervisors may
know closer prior art.

### 3.3 Comparison with existing approaches

| Approach | Representative | Strength | Documented weakness | What we take | What we add |
|---|---|---|---|---|---|
| Whole-file entropy threshold | Our Phase-I | Simple, fast | **Defeated** by entropy sharing / FPE / Base64 | Nothing (retire it as a *gate*) | Replace with segment classification + χ² + structural validity |
| Segment entropy classification | *Not on my watch* 2025 | F1 0.95–1.00 vs HEDGE 0.59–0.94 | Still content-based | Adopt the method | Fuse with structural + behavioural |
| ML on entropy-manipulated files | *Sensors* 25(8):2406 | 94.64% precision | Needs training data; content-only | Adopt the framing | Add behavioural families |
| Behavioural correlation (χ², repetitiveness) | ERW-Radar NDSS 2025 | 96.12% vs evasive; 5.09% CPU | Kernel/filesystem-level; **multi-process attacks bypass correlation** | Adopt the *repetitiveness* insight (our F2 self-similarity) | User-space; cross-process aggregation by directory scope |
| Deception / canary | IRDS4C; Elastic; Moore | ~12 s, very low FP | **Order-dependent**; cannot guarantee zero prior loss; skippable by aware attackers | Adopt canaries | **Order-robust layout + measured detection order** (C1) |
| Similarity hashing | MHAS SimHash; TLSH/ssdeep; minhash+banding | Variant-tolerant, fast, scales to 1M | Applied to **binaries/opcodes**, not filesystem behaviour | Adopt SimHash + banding | Apply to behavioural sessions; prove randomisation-invariance (C3) |
| EDR / behavioural AV | Commercial | Deep telemetry | **Killed first** (BYOVD, ETW suppression, SilentKill); AutoBypass 90% evasion vs Defender | Adopt the layered mindset | Tamper-evident liveness record; assume we *will* be attacked |
| Blockchain CTI | IRDS4C–CTIB and ~11 studied systems | Immutability, trust, provenance | **0.32 msg/s**; bandwidth unaddressed; 220 kB/incident on-chain | Adopt digest-on-chain, payload-off-chain | Remove from hot path entirely; scope to 3 operations (§1.4) |
| Recovery / backup-aware | Our existing `BackupManager` | Strict-clean rule genuinely prevents ciphertext-as-restore-source | **Reactive only** — snapshots after the fact | Keep it (it is good) | **Predictive** write-ahead snapshotting (C2) |
| Benchmarking | Splunk SURGe; Davies & Macfarlane 2026; NapierOne | Real strains, real throughput numbers | Reports *encryption* performance, not *defender* damage | Adopt NapierOne for corpus reproducibility | **Damage-before-containment** methodology (C5) |

### 3.4 Complete detection pipeline

```
FS/process/canary event
  → normalise + type + attribute (open-handle evidence → verified; else guess + confidence)
  → dedup (1 s window)                                   [existing, keep]
  → reject inode-reuse fake renames                       [existing, keep — genuinely good]
  → route to SESSION AGGREGATOR
       key = (process ∥ process-group, directory subtree)
       short window 30–60 s   (practitioner guidance: aggregate per process, not per event)
       long window  minutes   (ERW-Radar repetitiveness)
  → compute F1..F6 raw signals (all measured, none defaulted)
  → per-family anomaly score vs LEARNED per-directory baseline (not a constant table)
  → calibrate → p_f ∈ [0,1]
  → redundancy discount → cap → noisy-OR fuse → P
  → isotonic calibrate → P_cal
  → rule floor check (max of the two)
  → hysteresis / dwell-time check
  → emit DECISION {P_cal, band, authority, contributions, explanation, decision_id}
```

**Explicitly removed from detection:** the entropy hard gate; the 10-family extension signature
list as a *primary* signal (demoted to one corroborating token); whole-file entropy thresholding.

### 3.5 Complete response pipeline

```
DECISION (band, authority, attribution_confidence, decision_id)
  → POLICY ENGINE  (declarative; hash-anchored; per-band authority table)
  → SAFETY GATES
       · protected process list?          → refuse, record refusal
       · dry_run?                          → log intent, touch nothing
       · attribution_confidence < θ?       → cap authority at L2 (unless canary-triggered)
       · confirmation_required band?       → enqueue, surface on SOC, await operator
       · defender's own tooling?           → refuse (existing DEFENDER_TOOLING_MARKERS, keep)
       · path inside a defender store?     → never re-quarantine (existing, keep)
  → EXECUTE (ascending authority)
       L1 advise → dashboard
       L2 predictive write-ahead snapshot of inferred next targets   ★C2
       L3 suspend (SIGSTOP) + block writes by PID + snapshot in-flight file
       L4 terminate (verified) → quarantine → restore verified clean copy → rename-back
          → sweep session's other files → post-kill content verification
       L5 isolate subtree (operator-confirmed outside lab)
  → RECORD
       forensic bundle: observed values ONLY; requested vs ACTUAL outcome;
                        attribution_confidence; rollback token
       ledger append: hash-chained + HMAC tagged
       fingerprint: quantise session → SimHash → publish (digest anchored)
       rollback token persisted so containment can be undone
  → CONTINUE PROTECTING (agent never exits on incident)
```

### 3.6 Modules to KEEP (from the actual repository)

| Module | Reason |
|---|---|
| `entropy/entropy_calculator.py` | Correct Shannon; thirds; rename-aware history; baseline priming. **Extend**, don't replace |
| `monitoring/event_pipeline.py` | Inode-reuse fake-rename rejection, unbounded queue with observable backpressure, self-echo suppression |
| `monitoring/watchdog_monitor.py` (FileMonitor, SpeedTracker, dedup) | Solid capture layer |
| `CampaignTracker` | Best existing idea — becomes the seed of the session aggregator |
| `ProcessTerminator` + `_terminate_process` | Verified-identity-only, self-kill prevention, dry-run, zombie-aware. **Fails closed** |
| `FileQuarantine` | Dual hash, meta sidecar, never overwrites, read-only |
| `BackupManager` | Strict-clean rule + post-kill content verification + rename-back. Becomes the base for **L2 predictive snapshotting** |
| `benchmark/runner.py`, `scenarios.py`, `recovery_drill.py` | Real instrumentation driving the real decision chain; numbers reproduce exactly |
| `docs/limitations.md` discipline | Publishing 0/6 blind spot and 45.1% recovery is exactly right — extend it |
| `ai/rf_weights.json` + `train_rf.py` + `training_schema.py` | Genuine artifact, versioned schema, honest provenance |
| `catalog.py`, `safe_path()` confinement in `ransomware_engines.py` | Correct sandbox for safe synthetic malware |
| `control_authorized` (attacker console) | Correct `hmac.compare_digest` pattern — **reuse for the SOC API** |
| socket.io transport + dashboard layout | Works; only the data is wrong |

### 3.7 Modules to REMOVE

| Item | Size | Reason |
|---|---|---|
| `app.py /api/telemetry` | ~104 lines | Unauthenticated, destructive, fabricates detections |
| `_relay_telemetry` + 2 call sites | ~20 | Attacker must not author defender conclusions |
| `_simulate_network_exploit` | ~18 | Scripted fiction **and the direct cause of the demo deadlock** |
| All 19 hardcoded "success" defaults | — | `7.95`, `25576`, `"ransomware_ryuk.exe"`, `"a3b9f8d1e2c45678"`, `100.0`, `"dqn"`, `"QUARANTINED"`, `online: True`, `process_killed: True`, … |
| `ai/dqn_model.py` + `torch` | 711 lines, ~2 GB | No weights in repo, never default, logs "unavailable" every start |
| `eventlet` | dep | Unused (`async_mode="threading"`), deprecated upstream |
| `entropy_system.py`, `blockchain/blockchain_logger.py` | 115 | Deprecation facades with no callers in a one-commit repo |
| `LocalLedger` as the primary store | ~90 | No chain/hash/signature/verify — replaced, not patched |
| `TAMPER_CMDLINE_SIGNATURES` (Windows strings) | 7 | Cannot fire on the Linux demo host — replaced with platform-appropriate equivalents |
| `NORMAL_ENTROPY_RANGES` as a hand-written constant table | 14 entries | Replaced by a **learned, empirically derived** baseline |
| `is_known_process` feature | 1 | Literal duplicate of `is_signed` |
| `EVENT_QUEUE_SIZE`, `EVENT_BATCH_SIZE` | 2 | Dead config — either wire up or delete |
| The entropy hard gate in `_qualifies` / `make_decision` | 2 lines | The single worst design defect |
| `execute_response`'s procname rewrite to `"ransomware_simulator"` | 3 | Defender editing its own audit trail |

### 3.8 Modules to REWRITE

| Module | Why |
|---|---|
| `attacker_server/app.py` HTTP layer | Deadlock (`Lock` → `RLock`), remove theatre, honest attack-progress reporting into a **separated** red-team panel |
| `app.py` API surface | Read `outcome` not `status`; return `null` never constants; derive `online` from heartbeat age; token auth; CORS locked |
| `victim_server/app.py` vault + quarantine API | Restore real auth (`compare_digest` + session expiry); remove the 7 fabrications |
| `blockchain/connector.py` | Hash-chained + HMAC + Merkle + `verify()`; Ethereum demoted to optional 32-byte root anchor |
| `blockchain/fingerprint_exchange.py` | Re-key on behavioural SimHash, not content hash |
| `benchmark/exchange_simulation.py` | **Randomise payloads independently per tenant** — otherwise it proves nothing |
| RF feature layer (`ai/rf_model.py`) | 6 of 11 features have no producer; `process_age_sec` is constant 300.0 exactly when acting; `is_signed` misnamed. Rebuild the contract, retrain |
| `storage/database.py` schema | Add `terminate_result`, `quarantine_result`, `attribution_source`, `identity_verified` — removes the *need* to fabricate |
| `config.py` | No import-time `os.makedirs`; secrets from env with hard failure |
| `lab.py` | Restart crashed services; alert on death; don't take the whole lab down |
| `tests/` | Fix isolation (tmpdir + injected paths); merge root `test_blockchain.py`; update stale config test; fix `requirements-ci.txt` |

### 3.9 New modules to ADD

| Module | Pillar / gap |
|---|---|
| `agent/policy.py` — declarative protection policy + hash anchoring | §1.4 use 3 |
| `agent/supervisor.py` — liveness heartbeat, self-integrity, restart | G8 |
| `sensing/process_monitor.py` — tree, ancestry, I/O counters, per-PID file sets, **attribution confidence** | Objective #6 (currently absent) |
| `sensing/baseline_modeller.py` — learned per-directory resting distributions, versioned | Removes circular constant tables |
| `sensing/canary_grid.py` — **order-robust canary layout** + placement report | **C1** / G2 |
| `detection/format_validator.py` — structural parse per format | **Pillar 1** / G1 |
| `detection/segment_entropy.py` — windowed segment profile + trained classifier | *Not on my watch* |
| `detection/byte_distribution.py` — χ² vs type-specific benign distribution | ERW-Radar / G1 |
| `detection/self_similarity.py` — long-horizon segment χ² correlation (repetitiveness) | ERW-Radar |
| `detection/session_aggregator.py` — per-session evidence vectors, short + long windows | Practitioner guidance |
| `decision/fusion.py` — noisy-OR + caps + redundancy discount + isotonic calibration | **C4** |
| `decision/explainer.py` — per-family contributions + measured raw signals | Explainability |
| `response/predictive_snapshot.py` — **traversal-order inference + write-ahead snapshot** | **C2** / G3 / G6 |
| `response/policy_engine.py` — authority levels L0–L5, confirmation queue, rollback tokens | Your §9 safety controls |
| `fingerprint/behavioural.py` — quantise → shingles → SimHash → banded LSH index | **C3** |
| `audit/chained_ledger.py` — hash chain + HMAC + Merkle + `verify()` | **Pillar 3** / G7 |
| `intel/exchange.py` — behavioural-fingerprint registry + independent-node consensus | **C3** |
| `eval/damage_metrics.py` — files lost, bytes lost, decomposed latency | **C5** / G6 |
| `eval/evasion_battery.py` — entropy sharing, FPE-radix, Base64/ASCII85, partial, intermittent/split, benign-imitation, reverse-order, canary-skipping, multi-process | §1.1 / G1–G4 |
| `eval/baselines.py` — A entropy-only, B hash+entropy, C behaviour-only, D deception-only, E proposed, E−Fx ablations | Objective #21 |
| `eval/corpus/` — NapierOne-based + locally generated real files, with **published measured entropy distributions** | G5 |

### 3.10 Testing strategy

1. **Fix isolation first** — remove import-time `os.makedirs`; inject `DB_PATH`, store dirs, per-test tmpdir. (Currently `test_same_seed_produces_identical_files` fails only in full-suite order.)
2. **Repair the 5 genuine failing tests** — do not skip or delete; they assert correct behaviour (vault ×2, fail-open health ×2, stale config ×1).
3. **Real corpus** — genuine JPEG/PNG/MP4/ZIP/7z/TAR.GZ/PDF/DOCX/XLSX/SQLite via real encoders, plus NapierOne for reproducibility. **Re-derive every threshold empirically and publish the distributions.** (Our audit found the current fixtures are `bytes([i % 128])` → entropy exactly 7.00, with **PNG magic in files named `.jpg`** — circular by construction.)
4. **Legitimate workload battery** — document editing, copy, backup job, ZIP/7z creation, tar.gz, photo import, video write, git burst, CSV export, DB dump, `pip`/`npm` cache writes, VM image copy, encrypted-container creation, restic/borg backup.
5. **Schema-contract test** — assert every ML feature comes from a real producer, no defaults. Would have caught the train/serve skew mechanically.
6. **No-fabrication test** — grep the API layer for magic constants; assert every rendered field equals the DB value or is `null`.
7. **Failure injection** — kill detector (dashboard OFFLINE ≤ `PIPELINE_STALE_SECONDS`); kill dashboard (detection continues, events buffer); corrupt ledger (`verify()` names the entry); DB locked; disk full; permissions denied; 10 000-file burst (bounded queue, measured drops); network absent (intel degrades to local-only).
8. **Security tests** — vault requires PIN; SOC API requires token; `/api/telemetry` returns 404; CORS restricted; symlink-out-of-estate quarantine refused; filename with newline/ANSI/HTML sanitised and escaped; path traversal on report route refused.
9. **Determinism** — seeded scenarios, committed generator + committed artifact, timestamped report. (Extend the existing, correct pattern.)

### 3.11 Adversarial testing strategy

Implement each evasion as a **safe synthetic simulator** (no real malware), run against the full
agent, and apply the loop you specified: *record → explain why it worked → classify the weakness
→ fix → re-test → document*.

| # | Evasion | Grounded in | Expected outcome (hypothesis, to be measured) |
|---|---|---|---|
| A1 | **Entropy sharing** (implement Bang et al.'s scheme) | Sensors 24(5):1446 | Entropy family ≈ 0. **F1 structural + χ² should still fire.** This is the headline experiment |
| A2 | FPE radix manipulation to hit target entropy | Sensors 23(10):4728 | As A1 |
| A3 | Base64 / ASCII85 / Base32 encoding | Entropy 22(2):239 | Entropy drops; format validity fails hard |
| A4 | Partial encryption (first N KB only) | McIntosh; ERW-Radar | Segment classifier should localise it |
| A5 | Intermittent / split encryption | Benchmark paper: "frequent use of intermittent encryption… to evade detection" | Defeats windowed rate; **long-horizon self-similarity should catch it** |
| A6 | Low-and-slow (1 file / >16 s) | Defeats our current 15 s / 2-file campaign rule | Same |
| A7 | Benign imitation (Doppel-Paymer / ANIMAGUS style) | ERW-Radar §II | **Expected to partially succeed against us. Report honestly** |
| A8 | Reverse-order traversal | Moore 2016 | **Canary layout must still fire (C1)** |
| A9 | Random-order traversal | Hybrid decoy+entropy framework | As A8 |
| A10 | Canary-skipping (enumerate & exclude decoys) | IRDS4C challenge: "adversaries recognize and evade static decoy elements" | **Expected to defeat F5. Document as a real limitation** |
| A11 | Multi-process / distributed writes | ERW-Radar: multi-process bypasses correlation | **Expected to weaken F2. Document** |
| A12 | Extension-preserving in-place encryption | Our own `image_blindspot` 0/6 | F1 structural should close it |
| A13 | Rename-before-encrypt | — | F3 extension churn |
| A14 | Legitimate-process-name mimicry | Snatch names the binary as its own SHA-256; LOLBins | F4 ancestry + first-sight-binary |
| A15 | Defender-killing (attack our agent) | BYOVD, SilentKill, EDRKillShifter, T1562.001 | Supervisor + tamper-evident liveness gap in the ledger |
| A16 | Flood / overflow the detector | ERW-Radar evaluates this explicitly | Bounded queue, measured drops, no crash |
| A17 | Tamper with the audit ledger | — | `verify()` must name the exact broken entry |
| A18 | Poison the intel exchange | Existing ≥2-independent-node defence | Must not auto-quarantine from one node |

**Every result — including the ones we lose — gets published.** A documented 12/18 with three
honest remaining gaps is worth more to an evaluator than an unverified 18/18.

### 3.12 Evaluation metrics

**Detection quality:** Precision · Recall · F1 · ROC-AUC · PR-AUC · FPR · FNR · **false-quarantine count** (files destroyed by the defender — the critical safety metric) · calibration (Brier score, reliability diagram, ECE)

**Damage (our objective function — C5):** **files lost before containment** · **bytes lost before containment** · % of estate affected before containment · files recovered · recovery rate · RTO

**Latency (decomposed, per practitioner guidance):** event→aggregate · aggregate→decision · decision→action · **end-to-end event→containment** · wall-clock ms *and* file-operations · time-to-first-alert · time-to-contain

**Robustness:** detection rate per evasion variant A1–A18 · **per-family ablation** (drop detection when F1…F6 is removed) · canary detection order under forward/reverse/random/skipping traversal · variant generalisation (train on families X, test on unseen Y — targets RanSMAP's 0.55–0.71 recall gap)

**Cross-host (C3):** behavioural Hamming distance vs content-hash distance across independently randomised payloads · **time-to-contain on Host B with intel vs without** · intel precision (false-confirm rate)

**Overhead:** agent CPU% · RSS MB · disk I/O bytes · events/sec sustained · files/sec sustained · queue depth · drop count · ledger append latency · dashboard update latency — measured across idle / normal / heavy-legitimate / attack (compare against ERW-Radar's published 5.09% CPU / 3.80% memory as a reference point)

**Integrity:** ledger `verify()` pass/fail · tamper localisation accuracy · policy-hash match

### 3.13 Expected demonstrable outcomes

What an evaluator will **see**, and what they can **measure**:

| # | Demonstration | Measured claim |
|---|---|---|
| 1 | Agent starts, learns baseline, plants canaries, reports `PROTECTION ON` with protected dirs, process count, event count, risk band | Continuous operation, not a one-shot script |
| 2 | Normal workloads run (edit, ZIP, git, backup, photo import) | **0 false quarantines**; measured FPR |
| 3 | **Entropy-sharing attack**: entropy panel stays green while the detector fires | F1 contributes ~0; detection still ≥ threshold. **Directly refutes the Phase-I single point of failure** |
| 4 | **Reverse-order attack**: alphabetical canary would have been hit last; ours fires early | Detection order under 4 traversal permutations |
| 5 | **Predictive snapshot**: files recovered that were *never* backed up at baseline | Files-lost delta with L2 on vs off |
| 6 | In-place JPEG encryption (our current 0/6 blind spot) | Detection rate before vs after |
| 7 | Real suspend → real terminate of the correct PID; 18/18 restored; 0 `.WNCRY` | Already verified working — retain |
| 8 | Explanation panel: risk with per-family contributions, every value traceable | No field unbacked by data |
| 9 | **Flip one byte of the ledger on stage → `CHAIN BROKEN AT ENTRY n`** | Tamper detection + localisation |
| 10 | **Host A → Host B, independently randomised ciphertext → Host B contains faster** | Hamming distance small; content-hash distance maximal; time-to-contain delta |
| 11 | Kill the detector → dashboard red `OFFLINE` in ≤8 s; ledger shows the liveness gap | Fails **safe**, on purpose, on stage |
| 12 | 10 000-file burst → bounded queue, reported drops, no crash | Throughput + drop rate |
| 13 | Baseline table: A / B / C / D / E + E−Fx ablations | Proves the **architecture** wins, not just the model |
| 14 | Adversarial log: 18 evasions, N defeated, **M published as honest remaining gaps** | Systematic challenge + improvement |
| 15 | Overhead dashboard: CPU/RSS/IO idle vs attack | Compared against published references |

---

## 4. WHAT THIS PROJECT STILL CANNOT DO

Stated up front, because your §26 requires it and because the literature confirms each one:

- **Cannot guarantee zero files lost before detection.** Elastic states this is true even for
  kernel-level minifilter canaries (G3). We **bound** loss; we do not claim to prevent it.
- **Cannot defeat a canary-aware attacker** that enumerates and excludes decoys (A10). Documented.
- **Cannot fully match ERW-Radar** against benign-imitating ransomware (A7) or multi-process
  attacks (A11) from user space. We implement a simplified self-similarity detector and will
  report where it fails.
- **Cannot attribute file writes with kernel certainty.** User-space `psutil.open_files()` is a
  poll, not an event; a fast writer closes the handle before observation. eBPF or a minifilter
  would fix this (the eBPF honeypot literature shows the better approach) but is non-portable,
  needs root and kernel headers, and cannot be demonstrated on an examiner's laptop. **Explicitly
  out of scope, explicitly documented.**
- **Cannot decrypt ransomware output.** Recovery = restore from a pre-attack clean copy.
- **Cannot claim zero-day detection.** Behavioural generalisation to unseen families is testable;
  "detects all zero-day ransomware" is not.
- **Cannot claim zero false positives.** Any detector sensitive enough for low-and-slow will
  alert on some legitimate bulk operation. We claim a **measured, bounded** FPR and a **measured
  cost per false quarantine**.
- **Is not an EDR.** It is a research prototype of a defence agent, in a purple-team lab.
- **Cannot validate Windows-specific TTPs on Linux.** Platform must be decided (see §6).

---

## 5. WHAT WAS DELIBERATELY NOT ADDED (per your §18)

| Technology | Decision | Reason |
|---|---|---|
| eBPF | **NO** | Genuinely better attribution, but non-portable to Windows, needs root + kernel headers, undemonstrable on a laptop. Replaced by measured `psutil` + explicit `attribution_confidence` |
| Kernel minifilter | **NO** | Same, worse |
| Reinforcement learning | **NO** | An RL agent taking destructive filesystem actions is an unacceptable safety risk and cannot be validated in a semester. DQN removed |
| Federated learning | **NO** | We share *fingerprints*, not gradients. No model is trained across nodes |
| Kubernetes / containers orchestration | **NO** | Destroys reproducibility for a VTU demo |
| Post-quantum crypto | **NO** | No threat model requires it |
| IPFS | **NO** | Off-chain storage is a local directory; IPFS adds a dependency with no measurable benefit at this scale |
| Hyperledger Fabric | **NO** | The CTI literature notes Fabric's ordering service "assumes organizational cooperation rather than Byzantine fault tolerance"; far too heavy for a single-host demo |
| Full Ethereum node as primary | **NO** | 0.32 msg/s class of latency (G7). Optional 32-byte anchor only |
| Multiple languages | **NO** | Python throughout; no benefit |
| Deep learning on telemetry | **NO** | MHSA-LSTM and RanSMAP exist and need large corpora + GPU; a calibrated gradient-boosted/RF model on ~12 families is defensible, explainable and reproducible |

---

## 6. OPEN QUESTIONS BLOCKING IMPLEMENTATION

1. **The documents.** No Phase-I report, synopsis, literature review or base papers were supplied;
   the repo has zero citations. Phase 4 (base-paper comparison) remains blocked, and **C1–C5 must
   not be called novel until checked against your actual papers.** In particular: if your base
   paper is Bang et al. 2024, then §1.1 row 1 is your foundation and Pillar 1 is your direct
   response — please confirm.
2. **Demo platform: Windows or Linux?** The existing code assumes Windows (`svchost.exe`,
   `vssadmin`, `wbadmin`) but runs on Linux, so `TAMPER_CMDLINE_SIGNATURES` can never fire. This
   decides whether F4's recovery-tamper signals target Shadow Copies or `borg`/`restic`/`systemd`
   equivalents, and whether process ancestry uses ETW or `/proc`.
3. **Approval to remove** DQN/torch, eventlet, the deprecation facades, `/api/telemetry` and the
   fake exploit theatre.
4. **Corpus access.** NapierOne is freely available and was built specifically for ransomware
   reproducibility. Downloading multi-GB corpora may not be feasible in this environment — confirm
   whether to (a) generate a real-file corpus locally with real encoders, or (b) target NapierOne
   on your machine.
5. **Sequencing preference.** Stage 0 (make the existing demo work — 6 verified fixes, ~1 day,
   no research input needed) can proceed immediately and independently of everything above.
