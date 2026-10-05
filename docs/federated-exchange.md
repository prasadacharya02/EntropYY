# Cross-host threat intelligence in this project

**Status: implemented and measured. The interesting result is a negative one.**

## The finding this layer is built on

A content hash of ransomware ciphertext **cannot** identify a shared strain
across hosts. Each victim's ciphertext is randomised (fresh IV/nonce per file),
so the bytes — and therefore the SHA-256 — differ on every host and every run.
We measured exactly that in our own repository before building anything:

```
original file sha256:        9dd0f5ea35f5a722
Host-A ciphertext sha256:    caf473dac34f2205
Host-B ciphertext sha256:    a2be6e60c5a2fdae
Host-A run-2 sha256:         eda0ab7bf630248f

distinct hashes over 1000 encryptions of the SAME file: 1000 / 1000
```

Reproduce: `python -m benchmark.exchange_simulation` (see the
`exact_hash_channel` block of the artifact in `benchmark/results/`).

So this project runs **two independent channels**, and reports them separately
because they have different failure modes.

### Channel 1 — exact content hash (kept, with honest scope)

`blockchain/fingerprint_exchange.py` maps a full-file SHA-256 to sightings and
distinct node IDs. It works for artefacts that are **byte-identical by
construction** — a ransom note text is the same string on every victim — and it
is the right tool for that case. It is useless for ciphertext, and the project
no longer pretends otherwise.

The pipeline publishes to this channel only when all of the following hold:

1. the action was a **real** quarantine (not dry-run, not a simulated success),
2. the file's **exact** full-file digest was computed
   (`ENTROPY_CONTENT_HASH_MAX_BYTES`, default 256 MB),
3. the event is not from inside a defender store.

The sampled entropy digest is a *different value* and is never published as
exact intel.

### Channel 2 — behavioural fingerprint (the part that generalises)

`fingerprint/behavioral.py` builds a 64-bit SimHash over the **shape** of a
short operation sequence: event type, extension family, entropy bucket, entropy
delta bucket, rate bucket, extension-change flag, and format-integrity flag,
combined as unigrams, bigrams and trigrams. `blockchain/behavioral_exchange.py`
stores those signatures and answers nearest-neighbour queries by Hamming
distance.

Measured separation (`python -m benchmark.exchange_simulation`):

| Comparison | Hamming distance | Interpretation |
| --- | --- | --- |
| Same strain, **different host, independently randomised ciphertext** | **0** | identified as the same behaviour |
| Second host encounter (no ransom note) | **6** | inside the 6-bit match radius |
| Legitimate bulk backup workload | **15** | well outside the radius |

The ransom note is deliberately *not* required: the second-host encounter above
carries no note and still matches.

## The confirmation rule (and why it exists)

| Sightings | Flag | Effect |
| --- | --- | --- |
| unknown | none | nothing added |
| ≥ 1 node (near-neighbour cluster) | `known_threat` | **corroborating**: raises review risk |
| ≥ `ENTROPY_EXCHANGE_CONFIRM_THRESHOLD` (default 2) **distinct node IDs** | `confirmed` | review priority; see below |

Corroboration counts the whole near-neighbour cluster, not only bit-identical
signatures, because two hosts observing the same behaviour rarely produce
exactly equal SimHashes. Distinct node IDs are still required, so one noisy or
malicious node cannot confirm a signature by itself.

**A behavioural match never quarantines a file on its own.** In
`DecisionEngine.decide`, a confirmed match can raise an IGNORE to an ALERT
(review priority). Containment still requires the deterministic evidence in the
campaign layer. This is deliberate: a fuzzy signature is corroborating context,
not proof.

## What this is not

- **Not a network.** The registry is a single SQLite file opened by several
  simulated node identities. There is no replication, no transport, no
  Byzantine agreement. `GET /api/intel/status` reports
  `"scope": "local shared SQLite registry; not network-replicated"`.
- **Not a calibrated probability.** The risk index is an uncalibrated evidence
  aggregate and is labelled as such everywhere it is displayed.
- **Not a substitute for a signature database.** It clusters *behaviour*, not
  binaries.
- **Limited by session length.** A single-file, single-event session has no
  behavioural shape and does not match anything: our cold-start and
  single-sighting probes measure exactly that (distances of 30+ bits from the
  strain cluster). Correlation needs a few operations to become distinctive.

## Reproducing

```bash
python -m benchmark.exchange_simulation
# writes benchmark/results/exchange_simulation_<timestamp>.json
```

`python -m benchmark` embeds the same metrics in
`docs/benchmark-report.md` under "Cross-host intelligence".
