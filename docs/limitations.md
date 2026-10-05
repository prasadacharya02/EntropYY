# ENTROPY - Honest Limitations (Final Year Major Project)

This project is a **controlled teaching lab with industry-level engineering**, not endpoint protection. Every limitation below is published openly - no hidden failures.

## Detection - What Works & What Doesn't

- **Works**: Shannon entropy + format-integrity + campaign escalation. Measured live (2026-10-04 audit): first incident row 206 ms after launch, attacker process killed 1.0-1.4 s after launch, 1 of 43 files touched, that file quarantined and restored, 0 encrypted. Benchmark: 48/48 attack runs, 0/21 false positives, 0 false quarantines.
- **Limitation**: Process attribution is verified only when process has file open. Other guesses stored but cannot terminate. Best-effort, can be dodged by sophisticated malware.
- **Limitation**: Ransom-note signal is signature-based (filenames, phrase list). Unknown note wording with no matching filename relies on entropy/speed signals.
- **Limitation**: Defense-tamper signal watches backup_storage/ and quarantine_storage/ for deletions. Backup store's own housekeeping (manifest rewrites, temp files) exempted by name, but version evictions beyond ENTROPY_BACKUP_MAX_VERSIONS (default 10) can look like tampering - raises alert (safe direction, not missed attack).
- **Former blind spot, now closed structurally (with a stated boundary)**: `image_blindspot` (in-place encryption of high-entropy media, no rename) used to score 0/6. It is now 6/6 because a full-file rewrite of a `.png` breaks its chunk framing, and the format-integrity signal fires regardless of entropy. **The boundary:** an attacker who encrypts payload bytes while preserving valid container framing would still satisfy the format check. That variant is **not** in the battery and must not be reported as detected. Format-framed files only (.png/.jpg/.pdf/.zip/.docx/.xlsx/.mp4 and friends); unknown extensions are reported as `unchecked`, never as clean.

## AI - Honest Scope

- DQN weights optional. Without ai/dqn_weights.pth rule engine decides. Dashboard fields engine/confidence/explanation come from persisted events, not fabricated scores. Torch optional, fallback to rules.
- Training data synthetic, versioned schema_version 1, held-out split.
- **Risk index is uncalibrated.** The multi-signal score is a weighted noisy-OR over evidence families; it is an interpretable index, NOT a probability. Every surface that shows it is labelled `UNCALIBRATED`. A calibrated probability would need labelled real-world telemetry we do not have.
- Random Forest second classifier (ai/rf_weights.json, python -m ai.train_rf) trained on seeded synthetic data (11 features), opt-in engine ENTROPY_AI_ENGINE=rf. Measured: 48/48 attacks but 6 FQ on media, so NOT default. Rule engine keeps 0-FQ bar. SHAP per-incident, fallback to global importances if SHAP missing. Synthetic data does not predict real-world prevalence.
- Hard-confirmation signals (ransom note, defense tamper, exchange-confirmed fingerprint) applied BEFORE any learned engine, so no model can downgrade confirmed incident.
- **Cross-host correlation is behavioural, not content-hash based.** Measured: content hashes never match across hosts for randomised ciphertext (0 cross-host matches; 1000/1000 distinct for one file), while the behavioural SimHash puts the same strain on another host at Hamming distance 0 and a legitimate bulk backup workload at 15. A behavioural match raises review priority only; it never quarantines alone. See `docs/federated-exchange.md`.
- **Attribution of a file write to a process is best-effort.** User-space `psutil` polling is a poll, not an event; a short-lived writer can close its handle before it is observed. The response layer refuses to terminate on unverified attribution, and `attribution_source` is now recorded per event. eBPF or a kernel minifilter would fix this properly; both are out of scope (non-portable, root/kernel-headers required, not demonstrable on a laptop).

## Blockchain - Honest

- Modes explicit: ganache, fallback (local SQLite), none. Default fallback=true for demo (works without Ganache).
- The local fallback is a **hash-chained, tamper-evident** SQLite ledger (`prev_hash` + `record_hash` per row), labelled `mode_label: "Local SQLite hash-chain ledger (tamper-evident; not a blockchain)"`. It detects edits and deletions on verification, and `add()` refuses to append to a broken chain. It is **not** tamper-proof against an administrator who rewrites the whole database and recomputes every hash — that needs an external anchor, which this build does not configure. Demonstration: edit one field with `sqlite3`, then `GET /api/blockchain/status` reports `verified: false` and `record hash mismatch at ledger row N`.
- logThreat is onlyOwner. Set ENTROPY_WALLET_ADDRESS to deployer.
- Cross-host registry is one shared SQLite store with several simulated node identities - not a network, no replication, no consensus protocol. A behavioural match is corroborating evidence that can raise review priority; it never quarantines by itself and never replaces the deterministic campaign evidence. Independent-node threshold (default 2 distinct IDs) still applies, and corroboration counts the near-neighbour cluster rather than only bit-identical signatures.

## Simulator - Safety

- Attacker engines only touch victim_server/user_files via safe_path() check. Never place real documents there.
- Encryption is os.urandom() overwrite + rename to .WNCRY, no key, original destroyed. Quarantine holds ciphertext evidence for forensics, cannot be decrypted by anyone (honest - real ransomware also not decryptable without attacker key).

## Recovery - Honest

- Does NOT decrypt ransomware files - key held by attacker, no product can recover. Recovery = restoring known-good copy captured BEFORE attack.
- Backup capture additive (reads victim file, writes only to backup_storage/) runs every mode including dry-run.
- Restore candidates clean versions only, stored blob must verify SHA-256 before use. Event-time captures labeled clean under strict rule: inside file type's normal range with no 0.5 margin AND no ≥2.0 jump from previous clean. Stops office ciphertext 7.8-8.0 (inside lenient range) from being restored as clean. Trade-off: legitimate edit jumping entropy ≥2.0 makes post-edit non-restorable, falls back to older clean.
- Dry-run: restore simulated (backup verified, file left). ENTROPY_DRY_RUN=false: clean version restored in place after contained.
- Renamed file restored then renamed back to original name, only when original path free, never clobbers attacker file.
- Backup store bounded versions per file (ENTROPY_BACKUP_MAX_VERSIONS default 10). Files only ever existed encrypted not restorable.
- Clean version = entropy within file type's normal range at capture. Random/already-encrypted unknown file (entropy >6.8) never clean, contained but never auto-restored - deliberately refuses to restore encrypted-looking content.
- Deleting file outside protected store raises no signal, invisible to entropy (no file to sample) - published loss, not hidden.
- Recovery drill (python -m benchmark.recovery_drill) authoritative source for measured recovery rate and RTO, counts lost files explicitly.

## Quarantine Decryption - Brutally Honest

- Privileged user (victim_user / 1234) CANNOT decrypt quarantine files. Quarantine holds os.urandom() ciphertext, no key, original destroyed.
- Vault can list, view metadata, forensic reports, but not decrypt.
- This is honest - real ransomware also not decryptable without attacker key. Recovery via backup vault restore, not decryption.
- If you claim "privileged user can decrypt quarantine", you're lying and will fail viva.

## What We Fixed for Final Year (Industry Level)

- Campaign escalation (2+ files in 15s = TERMINATE) stops slow attacks at file 2, previously missed until last file
- Strict clean labeling prevents ciphertext becoming restore source (was bug: restored ciphertext as clean)
- Content-based post-kill verification (hash vs last clean) repairs mid-write files, no entropy false positives on jpgs
- Zombie-aware termination (reap in console finally, treat zombie as success) - instant kill rc=42 not FORCE KILLED after 3s
- SHA3-256 dual fingerprint (not just SHA-256) - industry standard
- Real-time socket.io push verified sub-second
- Neutral victim explorer (no encrypted counts)
- Install-time quarantine folder creation per spec
- Requirements fixed (was ResolutionImpossible due to shap 0.51 + numpy 1.26.4 conflict)

## Adversarial Battery - Measured (2026-10-04 audit)

Every technique was executed as a real child process against the live pipeline:

| Technique | Files | Detected | Note |
|---|---|---|---|
| Fast random overwrite burst | 20 | YES (20/20) | entropy delta + format + campaign |
| Extension camouflage (`.txt` kept) | 10 | YES (10/10) | format integrity + delta, not the extension |
| Low-and-slow random overwrite | 4 | YES (4/4) | entropy delta per file |
| **XOR / entropy-preserving substitution** | 10 | **NO** | content destroyed, entropy unchanged, unknown format -> nothing fires |
| **XOR low-and-slow** | 3 | **NO** | same, below every rate threshold |
| **Encryption outside the watched folders** | 5 | **NO** | inherent to watch-scope; nothing is collected |
| 200 legitimate files in one burst | 200 | correctly NOT flagged | velocity alone is not evidence (fixed this audit) |

The XOR class is the same limit the entropy-sharing literature reports: an attacker who preserves
the byte distribution defeats entropy analysis, and a `.txt` file has no container to validate.
Do not claim these are caught.

## Control Plane - Trust Model

`/api/launch`, `/api/stop`, `/api/pause`, `/api/resume`, `/api/speed`, `/api/reset` accept exactly:
loopback peers, a valid `Authorization: Bearer <token>` (`ENTROPY_CONTROL_TOKEN`, otherwise a
per-session token generated at startup), or a same-site browser request whose Origin/Referer host
matches the `Host`/`X-Forwarded-Host` it was served on. Everything else is 403 - verified on real
non-loopback sockets. Because the token is embedded in the console page, **having the page is
equivalent to having control**; put your own authentication in front if you ever expose it.

## Measured Overhead (2026-10-04 audit)

Pipeline process: **1.8 % CPU / 129 MB RSS idle**; **28 % mean CPU (110 % peak) / 131 MB RSS at
~10 files/s**, 43.7 MB written for 200 events (each event writes a forensic report). The 1 s
polling loop is the idle cost.

## For Examiners

This is working system with 191 tests pass, deterministic benchmark, live demo verified. Not PowerPoint. Show the kill, 18/18 restored, vault evidence, the ledger tamper demonstration, and the measured behavioural-vs-content-hash contrast. Don't claim zero files lost, network-replicated intelligence, a blockchain, quarantine decryption, entropy-preserving detection, or A/B/C baseline numbers - and remember velocity-only activity is deliberately not an alert.
