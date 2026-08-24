
## Hash-Searcher 🔍

A fast, asynchronous Python tool to check file hashes across VirusTotal, AbuseIPDB, Censys, WHOIS, and AlienVault OTX. Supports password-protected ZIP files and modern AES-256 encryption.

🚀 Features

Multi-engine search: Fetches data from VT, OTX, AbuseIPDB, Censys, and WHOIS simultaneously.

ZIP Intelligence: Detects ZIP files, prompts for a password, and hashes every file inside. Nested archives are not unpacked.

OSINT Formatting: Clean, text-wrapped terminal output for domains and IP relations.

Report Production: Automatically formatted output to either .json or PDF.

Cache System: Due to Censys's API calls needing time, I've implemented a json cache for ips that have been called for before.

🛠️ Setup

1. Clone the repo: `git clone https://github.com/yourusername/hash-searcher.git`
2. Install: `pip install -e .`  (add `[dev]` for the test suite)
3. Copy `.env.example.txt` to `.env` and fill in your VirusTotal, AlienVault OTX,
   AbuseIPDB, and Censys keys.

📖 Usage

    hash-searcher <file_path_or_hash> [-o report.json | report.pdf]

Accepts MD5, SHA-1, and SHA-256 digests, or a path to a file.
