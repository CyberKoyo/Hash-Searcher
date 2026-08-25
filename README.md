
## Hash-Searcher 🔍

A fast, asynchronous Python tool to check file hashes across VirusTotal, AbuseIPDB, Censys, WHOIS, and AlienVault OTX. Supports password-protected ZIP files and modern AES-256 encryption.

🚀 Features

Multi-engine search: Fetches data from VT, OTX, AbuseIPDB, Censys, and WHOIS simultaneously.

ZIP Intelligence: Detects ZIP files, prompts for a password, and hashes every file inside. Nested archives are not unpacked.

OSINT Formatting: Clean, text-wrapped terminal output for domains and IP relations.

Report Production: Automatically formatted output to either .json or PDF.

Cache System: Censys responses are cached in a SQLite database under your user cache directory (`$XDG_CACHE_HOME/hash-searcher/responses.db`, or `~/.cache/hash-searcher/responses.db`); the schema supports other providers, but only Censys is wired up today. Errors are never cached. Use `--no-cache` to bypass it or `--refresh` to force fresh calls.

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
