
## Hash-Searcher 🔍

A fast, asynchronous Python tool to check file hashes across VirusTotal, AbuseIPDB, Censys, WHOIS, and AlienVault OTX. Supports password-protected ZIP files and modern AES-256 encryption.

🚀 Features

Multi-engine search: Fetches data from VT, OTX, AbuseIPDB, Censys, and WHOIS simultaneously.

ZIP Intelligence: Automatically detects ZIP files, prompts for passwords, and hashes internal contents.

OSINT Formatting: Clean, text-wrapped terminal output for domains and IP relations.

Report Production: Automatically formatted output to either .json or PDF.

Cache System: Due to Censys's API calls needing time, I've implemented a json cache for ips that have been called for before.

🛠️ Setup

1. Clone the repo: git clone https://github.com/yourusername/hash-searcher.git

2. Install dependencies: `pip install -r requirements.txt`

3. Configure API Keys: * Copy .env.example to .env.

4. Fill in your API keys from VirusTotal, AlienVault, and AbuseIPDB.

📖 Usage
>Bash
>
> `python hash-searcher.py <file_path_or_hash> [-o [example.json] [example.pdf]]`
