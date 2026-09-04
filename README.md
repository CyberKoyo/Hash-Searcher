
## Hash-Searcher 🔍

A fast, asynchronous Python tool to check hashes, IPs, domains, and URLs across eleven intelligence sources. Five need no account at all, two more need only a free one, and four are commercial-tier keys. Supports password-protected ZIP files and modern AES-256 encryption.

🚀 Features

Multi-engine search: Fetches from every source that can answer for the indicator at hand, concurrently. See 🔌 Sources below for which need a key.

ZIP Intelligence: Detects ZIP files, prompts for a password, and hashes every member — but only the first is analyzed. The remaining hashes are listed as `not analyzed` and are never sent to the providers. Nested archives are not unpacked.

Verdict: Every run ends in MALICIOUS, SUSPICIOUS, CLEAN, or UNKNOWN, with every signal that produced it printed underneath. See below.

OSINT Formatting: Clean, text-wrapped terminal output for domains and IP relations.

Report Production: Automatically formatted output — JSON, PDF, CSV, or Markdown, chosen by the `-o` file extension. See 📤 Output formats.

Cache System: Every provider response is cached in a SQLite database under your user cache directory (`$XDG_CACHE_HOME/hash-searcher/responses.db`, or `~/.cache/hash-searcher/responses.db`). The TTL is chosen per source rather than shared — ThreatFox turns over hourly, RDAP registration data on the order of years — and the exact numbers are in the 🔌 Sources table. Errors are never cached, so a transient failure is not pinned for the full TTL. Use `--no-cache` to bypass it or `--refresh` to force fresh calls.

Rate Budget: VirusTotal calls are counted against **4 requests/minute and 500/day** and refused locally once either ceiling is reached, rather than being sent and rejected. **Those two numbers describe VirusTotal's free tier** — if your key is a paid one, pass `--ignore-budget` and neither applies. The tally is a second table in the same SQLite database, so a daily count survives between runs; only real requests are counted, so a cache hit costs nothing, and `--no-cache` does not turn the budget off (a run that caches nothing makes more requests, not fewer). A refused call says so at the point it is refused (`Skipping VirusTotal: rate budget exhausted, retry in 41s`) and is recorded as a source that *could not be reached*, never as one that *has no record* — the first is a fact about this run, the second would be a claim about the sample.

Local Static Analysis: Before any network call, a supplied file (not a bare hash) is inspected locally -- entropy, a file-type-versus-extension check, and printable-string/IOC extraction always run; PE parsing and YARA scanning run when their optional libraries are installed. See 🔬 Static Analysis below.

🛠️ Setup

1. Clone the repo: `git clone https://github.com/yourusername/hash-searcher.git`
2. Install: `pip install -e .`  (add `[dev]` for the test suite, `[static]` for local static analysis -- see 🔬 Static Analysis below)
3. Copy `.env.example.txt` to `.env` and fill in whichever keys you have.
   No key is mandatory — the tool runs and reports with an empty `.env` — but
   how much you get back depends on which you set. See 🔌 Sources, and read
   "What an empty .env actually gets you" there before assuming it is enough.

🧪 Tests

    pip install -e ".[dev]"
    python -m pytest tests/ -v

The suite is fully offline — no API keys and no network. Provider responses are
recorded fixtures under `tests/fixtures/`, and HTTP is mocked with respx.

📖 Usage

    hash-searcher <indicator | - > [-o report.EXT]
                  [--input-file PATH] [--pivot-depth N]
                  [--zip-password PASSWORD] [--no-cache] [--refresh]
                  [--ignore-budget] [--no-static] [--yara-rules DIR]

Accepts an MD5/SHA-1/SHA-256 digest, a path to a file, an IP address, a
domain, or a URL. Whichever it is decides which sources run — an IP goes to
the IP sources and never to VirusTotal's file endpoint, which cannot answer
for one.

**Defanged indicators are accepted as typed.** `hxxps://evil[.]example/path`,
`1[.]2[.]3[.]4`, and `evil[dot]com` are refanged before anything is looked
up, because that is the form an indicator arrives in after travelling
through a report, a ticket, or a mail gateway.

A CIDR range is recognized and declined rather than expanded: a `/16` is
65,536 rate-limited lookups, and no flag turns that on. Pass the addresses
you actually care about.

An argument that is also a filename on disk is treated as the file. A file
named `evil.example` in the working directory is hashed, not resolved.

    -o, --output PATH     write a report to this path; the extension picks
                          the format (see 📤 Output formats)
    --input-file PATH     read indicators from this file, one per line
    --pivot-depth N       follow domains discovered through crt.sh, N levels
                          deep (default 0 — no pivoting)
    --zip-password PASS   password for an encrypted ZIP; prompts if omitted
    --no-cache            ignore and bypass the cache
    --refresh             force fresh calls, then re-cache
    --ignore-budget       do not hold VirusTotal to 4 requests/minute and
                          500/day — those are the free tier's limits, and a
                          paid key is not bound by them
    --no-static           skip local static analysis (entropy, PE, YARA, strings)
    --yara-rules DIR      scan against this directory of .yar/.yara rules
                          instead of the default (see 🔬 Static Analysis)

📤 Output formats

`-o` picks the format from the extension. Every writer consumes the report
model, not the terminal output, so no format can drift from what the run
actually found.

| Extension | Format | What it is for |
| --- | --- | --- |
| `.json` | JSON report | The machine-readable record — every source, every error, the full verdict. |
| `.pdf` | PDF report | The document you attach to a case. |
| `.csv` | One spreadsheet row | A triage queue: N indicators sorted by score, filtered by source. |
| `.md`, `.markdown` | Markdown | A pasteable ticket or chat comment. |
| `.stix` | STIX 2.1 bundle | Ingest into a TIP: the sample, the infrastructure it contacted, and the relationships between them. |
| `.misp` | MISP event JSON | `POST /events` into MISP. Unpublished — fanning it out to connected instances is your call, not the tool's. |

Both `.stix` and `.misp` are JSON documents, and both get an extension of
their own because `.json` already means this tool's own report. Neither adds
a dependency: they are built with `json` and `uuid`. STIX ids are UUIDv5
rather than random, so re-running the same indicator produces a bundle that
diffs against the last one instead of importing as a second, unrelated set
of objects.

An extension nothing writes is refused with the list above rather than
written as some default — and in a batch it is refused **before** the first
lookup, so a run does not spend its rate limit on reports it cannot write.

**Batches.** Pass `-` to read indicators from stdin, or `--input-file PATH`
to read them from a file — one per line, with blank lines and `#` comments
skipped, so a list pasted straight out of a report works:

    cut -f2 iocs.tsv | hash-searcher -
    hash-searcher --input-file iocs.txt -o report.json

A batch opens **one** cache and **one** rate budget for the whole run, so two
indicators that share a contacted IP cost one lookup rather than two, and the
VirusTotal quota is spent by the run rather than by the line. It runs serially
on purpose: every provider here rate limits, and N indicators at once would
multiply the request rate by N. Serial is not enough for VirusTotal on its
own, though — four requests a minute is a ceiling a five-line list reaches
without ever running two lookups at once, which is what the budget is for.

With `-o`, each indicator gets its own file — `report-1-198.51.100.10.json`,
`report-2-evil.example.json` — rather than the same path being overwritten
once per indicator. The exit code is the **most severe** of the runs, not the
last: a batch that found one malicious sample exits `2` even if everything
after it was clean.

**Pivoting.** `--pivot-depth N` takes the sibling domains crt.sh reported and
looks *those* up too, N levels deep. It is off by default.

The walk is breadth-first with a visited set and a hard ceiling of **20 extra
domain lookups per run, whatever N is** (`PIVOT_FETCH_BUDGET` in
`src/hash_searcher/api/api_data_puller.py`). That ceiling counts *domains*,
not requests: each pivoted domain costs one crt.sh call plus one RDAP
lookup, and RDAP bootstraps through a redirect, so 20 domains is closer to
60 HTTP requests than to 20. That ceiling is not a
performance tuning knob: a certificate log routinely names hundreds of
siblings, so depth 2 over 50 domains is thousands of requests against
providers that all rate limit, and depth 5 unbounded does not terminate in
any useful sense. The visited set matters for the same reason — certificate
logs are full of cycles, where two names on one certificate each name the
other.

🔬 Static Analysis

Before any provider is contacted -- and even with no API key configured at
all -- a supplied file (not a bare hash) is read locally and passed through
a handful of static analyzers. None of them execute, unpack, or otherwise
run the sample -- they only read bytes and parse structures. Every analyzer
bounds how much it reads or how long it can run: entropy and strings cap
the bytes read from the file, PE section entropy caps the bytes hashed per
section, and YARA scanning caps both the number of rule files it will
consider and the total wall-clock time it can spend across all of them --
a hostile input, or an accidental `--yara-rules ~`, cannot hang the tool.
When a cap actually truncates something, the report says so in a `note`
rather than silently showing a partial result as a complete one.

Three of the analyzers always run, using only the standard library:

- **Entropy**: Shannon entropy over the first 8 MiB. Above 7.2 bits/byte is
  flagged `packed` -- compressed or encrypted data, which for an executable
  usually means a packer.
- **File type**: the first bytes are checked against a small signature
  table (PE, ELF, PDF, ZIP) and compared against the file's extension; a
  mismatch is reported, an unrecognized type never is.
- **Strings**: printable ASCII/UTF-16 strings are extracted and scanned for
  IP addresses, domains, and URLs. IPs harvested this way are fed into the
  same AbuseIPDB/Censys/WHOIS enrichment as IPs VT reports -- so a sample
  nobody has ever uploaded to VT can still surface indicators.

Two more analyzers need optional libraries that are **not** installed by
default. Install them with:

    pip install 'hash-searcher[static]'

which adds `pefile`, `yara-python`, and `python-magic`. Without it, the
tool runs exactly as before -- the gated analyzers are named in the
report's `Skipped:` line rather than failing the run, and the file-type
check falls back to the built-in signature table instead of `python-magic`.

- **PE parsing** (`pefile`): imports, sections, and the build timestamp of
  a Windows PE file, plus a short list of imported APIs commonly associated
  with process injection or evasion.
- **YARA scanning** (`yara-python`): the sample is matched against every
  `.yar`/`.yara` file under a rules directory. **No rules ship with this
  tool** -- open rulesets are large, fast-moving, and variously licensed,
  so you supply your own. The default directory is
  `$XDG_DATA_HOME/hash-searcher/yara/` (or `~/.local/share/hash-searcher/yara/`
  if `XDG_DATA_HOME` is unset); a missing directory is a quiet empty
  result, not an error. Point at a different directory with
  `--yara-rules DIR`.

`python-magic` additionally needs the system `libmagic` library, which is a
separate install from the Python package:

    apt install libmagic1

Without it, `python-magic` fails to import and the file-type check silently
falls back to the built-in signature table, same as without the extra at
all.

Run `hash-searcher` with `--no-static` to skip this pass entirely.

Static analysis is heuristic, not a verdict. High entropy, an unusual
import, or a YARA hit is something to look at, not proof of anything --
**a packed binary is not automatically malicious**; plenty of legitimate
software is packed or compressed. All three findings feed the score (see
🎯 Verdict below), but only `suspicious_imports` and `yara_local` can pull
a file that VT has never seen out of the default `UNKNOWN` on their own --
each is independent evidence of malice by itself. `packed` still adds its
points to the score once something else has already escaped `UNKNOWN`, but
being packed alone is never enough: it means the tool could not see inside
the file, not that it found something bad there, so a packed installer VT
has never seen still reports `UNKNOWN` rather than a false `CLEAN`.

Static analysis runs even when no provider is reachable at all -- no
network, no `.env`, none of `TOTAL_KEY`/`OTX_KEY`/`IPDB_KEY`/`CENSYS_KEY`
set. In that case the tool prints "Continuing with local static analysis
results only," still renders a `STATIC ANALYSIS` section and a verdict
from whatever the local analyzers found, and exits accordingly -- it does
not print `Invalid hash` or bail with nothing to show. The same is true
when VirusTotal has simply never seen the file (a 404 with no OTX pulses):
the online sources are reported as having no record, but a populated
static report is never discarded to make room for that message.

🎯 Verdict

The tool does not stop at dumping provider data — it scores what it found and
says so. The score is a sum of weighted signals; the level is a band on that
sum:

| Level | When | Meaning |
|---|---|---|
| `MALICIOUS`  | score >= 50 | Strong, corroborated evidence. |
| `SUSPICIOUS` | score >= 15 | Something fired, but not enough to convict. |
| `CLEAN`      | below that  | VT has a record of the file and the evidence did not reach the suspicious threshold. |
| `UNKNOWN`    | VT has no record of the file **and** local static analysis found no `suspicious_imports` or `yara_local` finding | Nobody has analyzed this sample, online or locally. Not the bottom of the scale — a distinct answer, and it preempts the bands: OTX pulses are reported as a signal but cannot make an unanalyzed file `CLEAN`, and neither can `packed` alone. A `suspicious_imports` or `yara_local` finding is independent evidence the tool itself examined the file and found something, so it escapes this guard even with zero VT record — the file falls through to `CLEAN`/`SUSPICIOUS`/`MALICIOUS` on the score like any other. `packed` still contributes its points once escaped this way, but cannot cause the escape by itself. |

The signals and their weights, all of them in `src/hash_searcher/scoring.py`:

| Signal | Points | Fires when |
|---|---|---|
| detection | +50 / +20 / +10 | VT engines flag the file — +50 once 5 or more agree, +20 for 1–4, +10 when none convict but 3 or more call it suspicious |
| sigma     | +15 each high, +5 each medium, **capped at 30** | Crowdsourced Sigma rules matched. Capped because it is the only term that scales with the input, and the corpus fires readily on benign installers — behaviour alone reaches SUSPICIOUS, never MALICIOUS |
| family    | +15 | VT names a malware family |
| sandbox   | +15 | A sandbox returned a malicious verdict |
| yara      | +10 | A crowdsourced YARA rule matched |
| otx       | +10 | OTX pulses reference the indicator |
| abuseipdb | +10 | A contacted IP scores 75% or higher on AbuseIPDB |
| signed    | **-20** | A valid, verified code signature, **and no engine flagged the file** — evidence *against*. Suppressed once any engine convicts, because a signature is attacker-attached metadata and must not erase independent detections |
| packed    | +10 | Local entropy analysis flags the file as packed (see 🔬 Static Analysis) |
| suspicious_imports | +15 | A locally-parsed PE imports 3 or more APIs associated with process injection or evasion |
| yara_local | +20 | A local YARA rule (from `--yara-rules` or the default rules directory) matched |
| bazaar    | +15 | MalwareBazaar holds this exact sample, usually with a family name |
| threatfox | +15 | ThreatFox attributes the sample **or any contacted IP** to a malware family. Its dataset is overwhelmingly C2 addresses, so the per-IP half is usually the half that fires |
| kev       | +25 | A contacted host exposes a CVE CISA lists as known-exploited |
| internet_noise | −10 | GreyNoise calls a contacted IP benign internet background noise — scanning everyone is not evidence about *this* sample |

Certificate-transparency siblings score **nothing** on purpose. They are a
pivot, not a verdict; scoring them would make every large hosting provider
look malicious.

These weights are a coarse triage aid, not a classifier. They are constants at
the top of one file precisely so you can argue with them and change them.

🔌 Sources

| Source | Key | Indicators | Cache TTL | What it contributes |
|---|---|---|---|---|
| VirusTotal | `TOTAL_KEY` | hash | 24h | Detection ratio, Sigma rules, sandbox verdicts, contacted IPs and domains |
| AlienVault OTX | `OTX_KEY` | hash, ip, domain | 24h | Threat pulses and ATT&CK techniques |
| AbuseIPDB | `IPDB_KEY` | ip | 24h | Abuse confidence and report counts for contacted IPs |
| Censys | `CENSYS_KEY` | ip | 24h | ASN, org, country, open ports, reverse DNS |
| MalwareBazaar | free `ABUSECH_KEY` | hash | 24h | Malware family, tags, file type, YARA rules — names families VT may only call `trojan.generic` |
| ThreatFox | free `ABUSECH_KEY` | hash, ip, domain | 1h | IOC → family attribution with a confidence level |
| Shodan InternetDB | none | ip | 24h | Open ports, CPEs, and known CVEs per contacted IP |
| GreyNoise Community | optional `GREYNOISE_KEY` | ip | 24h | Whether an IP scans the whole internet or was aimed at you |
| crt.sh | none | domain | 24h | Sibling domains from certificate transparency (at most the first 10 contacted domains — it is serial and slow) |
| RDAP | none | domain | 7d | Domain registration dates and registrar |
| CISA KEV | none | (catalog) | 7d | Which CVEs on contacted hosts are confirmed exploited in the wild |

`GREYNOISE_KEY` is **optional**: GreyNoise Community answers without a key and
the key only raises the rate limit, so leaving it unset costs no coverage.

If the CISA KEV catalog cannot be fetched when there were CVEs to check, the
report says so and names how many went unchecked — an empty
KNOWN EXPLOITED VULNERABILITIES section always means "none matched", never
"nobody could ask".

RDAP has gaps the old `whois` library did not: `.de`, `.jp`, and `.io` run no
public RDAP server, and those report "No RDAP server for this TLD" rather than
being confused with a domain that is simply unregistered.

`ABUSECH_KEY` is free (one account at <https://auth.abuse.ch/> covers both
MalwareBazaar and ThreatFox). Both APIs were open when this tool first added
them and now answer `401 {"error": "Unauthorized"}` without a key, so they are
skipped when it is unset rather than failing on every run.

**What an empty `.env` actually gets you.** Five sources still run — Shodan
InternetDB, GreyNoise Community, crt.sh, RDAP, and CISA KEV — but every one of
them answers for an **IP or a domain**, not for a hash. So:

- `hash-searcher <a bare hash>` with no keys returns an empty report. Nothing
  in the keyless set can say anything about a hash it was handed on its own.
- `hash-searcher <a file>` with no keys still works, because local static
  analysis extracts IPs and domains from the file's strings and those feed the
  keyless IP and domain sources — that is how the Shodan → CVE → CISA KEV chain
  fires with nothing configured.
- Setting the free `ABUSECH_KEY` is what restores hash-level answers without a
  commercial key: MalwareBazaar and ThreatFox both take a hash.

VirusTotal remains the only source that turns a hash into contacted IPs and
domains, so a `TOTAL_KEY` still multiplies what every other source can reach.

CISA KEV is not a per-indicator lookup — it is a ~1MB catalog, downloaded at
most once per run and only when Shodan actually reported CVEs to intersect it
against, then matched locally. That is why it is the one source that is not a
registry `Provider`: the registry's contract is `fetch(client, indicator)`, and
a catalog takes no indicator.

Censys, crt.sh, and GreyNoise rate limit hard enough that their lookups run
serially with a gap between requests. Every request identifies the tool by
User-Agent, which several of these services ask for and crt.sh throttles
harder without.

WHOIS used to come from the `whois` PyPI package, which raised parse errors,
socket errors, and `UnicodeDecodeError` indiscriminately and had to be wrapped
in a bare `except Exception`. It is gone: registration data now comes from RDAP
over the same HTTP path as every other source, with the same retries, backoff,
and error handling. One caveat that came with the swap — a TLD with no public
RDAP server (`.de`, for instance) now reports an explicit error rather than a
silent row of `N/A`.

🚦 Exit codes

| Code | Verdict | Use |
|---|---|---|
| `0` | CLEAN | Nothing found against it. |
| `1` | SUSPICIOUS | Worth a human look. |
| `2` | MALICIOUS | Treat as malicious. |
| `3` | UNKNOWN | No provider has seen it — and also the code for an unusable run (bad path, no data), because a script should treat both alike. |

An unrecognized level fails safe to `3`, never to `0`.

For a batch, the exit code is the most severe of the individual runs, ranked
MALICIOUS > SUSPICIOUS > UNKNOWN > CLEAN — which is deliberately not the
numeric order of the codes, since UNKNOWN is `3` and MALICIOUS is `2`. A
batch with nothing to check exits `3`, never `0`.

📋 Report sections

Beyond the Sigma-rule listing, a run prints the verdict and its signals, the VT
detection ratio, an attribution block (family, code signature, sandbox verdicts,
YARA matches, PE metadata, submission history, and resolved MITRE ATT&CK
techniques), contacted domains, and — when VT reports contacted IPs — the
AbuseIPDB table, Censys enrichment, and WHOIS records for those IPs. Sections
with nothing to say stay silent rather than printing an empty frame.

The Phase 4 sources add their own sections: MALWAREBAZAAR and THREATFOX for
family attribution, IP INTELLIGENCE (Shodan ports/CVEs, the GreyNoise
noise-versus-targeted call, and ThreatFox's C2 family attribution) per
contacted IP, KNOWN EXPLOITED VULNERABILITIES
for any CVE in the CISA KEV catalog, and CERTIFICATE TRANSPARENCY for sibling
domains. The sibling list is capped at 100 names but always prints the
untruncated total, because a truncated list that reads as complete is worse
than none.

When a file (not a bare hash) is analyzed and `--no-static` was not passed, a
STATIC ANALYSIS section prints the local findings — entropy, file-type
mismatch, PE summary, YARA hits, and extracted-string counts — followed by
`Skipped:` and `Failed:` lines that are always printed, by name, even when
both are empty; a section that goes silent instead is indistinguishable from
one with nothing to report.

🗺️ MITRE ATT&CK

Technique IDs from VT and OTX are resolved to names, tactics, and links against
a reduced ATT&CK Enterprise STIX bundle vendored at
`src/hash_searcher/data/mitre-attack-enterprise.json` — resolution makes no
network call, so the offline guarantee holds. Provenance, the pinned release
tag, both SHA-256 digests, and the refresh command are in
[`src/hash_searcher/data/README.md`](src/hash_searcher/data/README.md).
