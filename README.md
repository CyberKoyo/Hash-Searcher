
## Hash-Searcher 🔍

A fast, asynchronous Python tool to check file hashes across VirusTotal, AbuseIPDB, Censys, WHOIS, and AlienVault OTX. Supports password-protected ZIP files and modern AES-256 encryption.

🚀 Features

Multi-engine search: Fetches data from VT, OTX, AbuseIPDB, Censys, and WHOIS simultaneously.

ZIP Intelligence: Detects ZIP files, prompts for a password, and hashes every member — but only the first is analyzed. The remaining hashes are listed as `not analyzed` and are never sent to the providers. Nested archives are not unpacked.

Verdict: Every run ends in MALICIOUS, SUSPICIOUS, CLEAN, or UNKNOWN, with every signal that produced it printed underneath. See below.

OSINT Formatting: Clean, text-wrapped terminal output for domains and IP relations.

Report Production: Automatically formatted output to either .json or PDF.

Cache System: VirusTotal, OTX, AbuseIPDB, and Censys responses are cached in a SQLite database under your user cache directory (`$XDG_CACHE_HOME/hash-searcher/responses.db`, or `~/.cache/hash-searcher/responses.db`), each with its own TTL. WHOIS is not cached. Errors are never cached, so a transient failure is not pinned for the full TTL. Use `--no-cache` to bypass it or `--refresh` to force fresh calls.

🛠️ Setup

1. Clone the repo: `git clone https://github.com/yourusername/hash-searcher.git`
2. Install: `pip install -e .`  (add `[dev]` for the test suite)
3. Copy `.env.example.txt` to `.env` and fill in your VirusTotal, AlienVault OTX,
   AbuseIPDB, and Censys keys.

🧪 Tests

    pip install -e ".[dev]"
    python -m pytest tests/ -v

The suite is fully offline — no API keys and no network. Provider responses are
recorded fixtures under `tests/fixtures/`, and HTTP is mocked with respx.

📖 Usage

    hash-searcher <file_path_or_hash> [-o report.json | report.pdf]
                  [--zip-password PASSWORD] [--no-cache] [--refresh]

Accepts MD5, SHA-1, and SHA-256 digests, or a path to a file.

    -o, --output PATH     write a report to this path (.json or .pdf)
    --zip-password PASS   password for an encrypted ZIP; prompts if omitted
    --no-cache            ignore and bypass the cache
    --refresh             force fresh calls, then re-cache

🎯 Verdict

The tool does not stop at dumping provider data — it scores what it found and
says so. The score is a sum of weighted signals; the level is a band on that
sum:

| Level | When | Meaning |
|---|---|---|
| `MALICIOUS`  | score >= 50 | Strong, corroborated evidence. |
| `SUSPICIOUS` | score >= 15 | Something fired, but not enough to convict. |
| `CLEAN`      | below that  | Providers know the file and nothing flagged it. |
| `UNKNOWN`    | VT has no record of the file and OTX has no pulses | Nobody has seen this sample. Not the bottom of the scale — a distinct answer. |

The signals and their weights, all of them in `src/hash_searcher/scoring.py`:

| Signal | Points | Fires when |
|---|---|---|
| detection | +50 / +20 | VT engines flag the file — +50 once 5 or more agree, +20 for 1–4 |
| sigma     | +15 each high, +5 each medium | Crowdsourced Sigma rules matched |
| family    | +15 | VT names a malware family |
| sandbox   | +15 | A sandbox returned a malicious verdict |
| yara      | +10 | A crowdsourced YARA rule matched |
| otx       | +10 | OTX pulses reference the indicator |
| abuseipdb | +10 | A contacted IP scores 75% or higher on AbuseIPDB |
| signed    | **-20** | A valid, verified code signature — evidence *against* |

These weights are a coarse triage aid, not a classifier. They are constants at
the top of one file precisely so you can argue with them and change them.

🚦 Exit codes

| Code | Verdict | Use |
|---|---|---|
| `0` | CLEAN | Nothing found against it. |
| `1` | SUSPICIOUS | Worth a human look. |
| `2` | MALICIOUS | Treat as malicious. |
| `3` | UNKNOWN | No provider has seen it — and also the code for an unusable run (bad path, no data), because a script should treat both alike. |

An unrecognized level fails safe to `3`, never to `0`.

📋 Report sections

Beyond the Sigma-rule listing, a run prints the verdict and its signals, the VT
detection ratio, an attribution block (family, code signature, sandbox verdicts,
YARA matches, PE metadata, submission history, and resolved MITRE ATT&CK
techniques), contacted domains, and — when VT reports contacted IPs — the
AbuseIPDB table, Censys enrichment, and WHOIS records for those IPs. Sections
with nothing to say stay silent rather than printing an empty frame.

🗺️ MITRE ATT&CK

Technique IDs from VT and OTX are resolved to names, tactics, and links against
a reduced ATT&CK Enterprise STIX bundle vendored at
`src/hash_searcher/data/mitre-attack-enterprise.json` — resolution makes no
network call, so the offline guarantee holds. Provenance, the pinned release
tag, both SHA-256 digests, and the refresh command are in
[`src/hash_searcher/data/README.md`](src/hash_searcher/data/README.md).
