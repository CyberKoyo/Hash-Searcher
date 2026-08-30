"""Shared dataclasses.

analysis/ produces these, render/ consumes them. Nothing here does I/O or
formatting -- that is the whole point of the split.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SigmaRule:
    title: str
    description: str
    level: str


@dataclass(frozen=True)
class AttackTechnique:
    id: str
    name: str
    tactic: str | None = None
    url: str | None = None


@dataclass(frozen=True)
class Detection:
    """VT's last_analysis_stats, reduced to the five verdict buckets.

    VT also reports failure/type-unsupported/confirmed-timeout; those are
    engine bookkeeping, not verdicts, and VT's own UI leaves them out of the
    denominator. Counting them would silently deflate every ratio.
    """
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0

    @property
    def total(self) -> int:
        return (self.malicious + self.suspicious + self.harmless
                + self.undetected + self.timeout)

    @property
    def ratio(self) -> str:
        return f"{self.malicious}/{self.total}"


@dataclass(frozen=True)
class ThreatClass:
    label: str
    family: str | None = None
    categories: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Submission:
    first_seen: str | None = None
    times_submitted: int = 0
    names: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Signature:
    verified: bool = False
    signer: str | None = None
    product: str | None = None


@dataclass(frozen=True)
class SandboxVerdict:
    sandbox: str
    category: str
    malware_names: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    author: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class PEInfo:
    imphash: str | None = None
    entry_point: int | None = None
    sections: int = 0
    compiled: str | None = None


@dataclass
class VTReport:
    found: bool
    sigma: list[SigmaRule] = field(default_factory=list)
    contacted_ips: list[str] = field(default_factory=list)
    contacted_domains: list[str] = field(default_factory=list)
    error: str | None = None
    detection: Detection | None = None
    threat: ThreatClass | None = None
    submission: Submission | None = None
    signature: Signature | None = None
    sandbox: list[SandboxVerdict] = field(default_factory=list)
    yara: list[YaraMatch] = field(default_factory=list)
    pe: PEInfo | None = None
    techniques: list[AttackTechnique] = field(default_factory=list)

    def by_level(self, level: str) -> list[SigmaRule]:
        return [r for r in self.sigma if r.level == level]


@dataclass
class OTXReport:
    """Two flags, two genuinely different questions.

    `otx_responded` answers "did OTX return a pulse_info block at all";
    `has_pulses` answers "does that block contain any pulses". They are not
    redundant -- OTX answering with an empty pulse list is real data, and
    conflating the two is what caused ruling R28.
    """

    #: int when OTX reported a count, else the string it substitutes
    #: ("N/A, No recorded instances", or "N/A" on an error). Typed for both
    #: because it genuinely holds both; `object` said nothing at all.
    recorded_instances: int | str
    attack_techniques: list[str] = field(default_factory=list)
    error: str | None = None
    #: bool(pulse_info["pulses"]) -- OTX has at least one pulse for this
    #: indicator.
    has_pulses: bool = False
    #: bool(pulse_info) -- OTX returned a pulse_info block, whatever is in it.
    otx_responded: bool = False
    techniques: list[AttackTechnique] = field(default_factory=list)


@dataclass
class IPReport:
    ip: str
    confidence: int = 0
    reports: int = 0
    hostnames: list[str] = field(default_factory=list)
    domain: str | None = None


@dataclass
class CensysHost:
    ip: str
    org: str | None = None
    asn: int | None = None
    country: str = "N/A"
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    new_hostnames: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class WhoisRecord:
    domain: str
    created: str = "N/A"
    expires: str = "N/A"
    registrar: str = "N/A"
    error: str | None = None


@dataclass
class BazaarReport:
    """MalwareBazaar's answer for one hash.

    found=False with error=None is a real answer -- the repository has
    never seen this sample. found=False with an error set means the
    lookup failed and nothing is known either way.
    """
    found: bool = False
    family: str | None = None
    tags: list[str] = field(default_factory=list)
    file_type: str | None = None
    first_seen: str | None = None
    yara: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ShodanReport:
    """Shodan InternetDB's answer for one IP.

    An all-empty report with error=None means Shodan has never scanned the
    address -- a real answer, not a failure.
    """
    ports: list[int] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class GreyNoiseReport:
    """Whether an IP is internet background noise or was aimed at you."""
    seen: bool = False
    classification: str | None = None
    name: str | None = None
    last_seen: str | None = None
    error: str | None = None


@dataclass
class CertReport:
    """Sibling domains from certificate transparency.

    `siblings` is capped at analysis.crtsh.SIBLING_LIMIT for readability;
    `count` is the untruncated total, so a capped list never reads as the
    whole answer.
    """
    siblings: list[str] = field(default_factory=list)
    count: int = 0
    error: str | None = None


@dataclass
class ThreatFoxReport:
    """ThreatFox's family attribution for one indicator."""
    found: bool = False
    malware: str | None = None
    confidence: int = 0
    tags: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class KEVEntry:
    """One CVE CISA has confirmed is exploited in the wild."""
    cve: str
    vendor: str | None = None
    product: str | None = None
    name: str | None = None
    date_added: str | None = None
    ransomware: bool = False


@dataclass(frozen=True)
class Signal:
    name: str
    points: int
    detail: str


@dataclass(frozen=True)
class Verdict:
    level: str
    score: int
    signals: list[Signal] = field(default_factory=list)


@dataclass(frozen=True)
class EntropyReport:
    overall: float = 0.0
    packed: bool = False
    note: str = ""


@dataclass(frozen=True)
class FileTypeReport:
    detected: str | None = None
    extension: str = ""
    mismatch: bool = False
    note: str = ""


@dataclass(frozen=True)
class PESection:
    name: str
    size: int = 0
    entropy: float = 0.0
    executable: bool = False


@dataclass(frozen=True)
class PEStaticReport:
    imports: dict[str, list[str]] = field(default_factory=dict)
    sections: list[PESection] = field(default_factory=list)
    compiled: str | None = None
    suspicious_imports: list[str] = field(default_factory=list)
    #: Set only when this PE could not be parsed at all -- mutually
    #: exclusive with a populated `sections`/`imports`. Distinct from
    #: `section_entropy_note` below, which can be set on an otherwise
    #: successful parse.
    note: str = ""
    #: Non-empty when one or more sections' entropy was computed over a
    #: bounded prefix rather than the section's full (attacker-controlled)
    #: claimed size -- see static/pe.py's SECTION_ENTROPY_CAP and
    #: branch-review.md I1. A silently truncated number is worse than a
    #: stated one.
    section_entropy_note: str = ""


@dataclass(frozen=True)
class YaraHit:
    rule: str
    namespace: str = "default"
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class IOCSet:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StringsReport:
    count: int = 0
    iocs: IOCSet = field(default_factory=IOCSet)


@dataclass
class StaticReport:
    """One assembly point for every local static analyzer.

    `skipped` and `failed` name analyzers, not libraries: an analyzer
    lands in `skipped` when its capability gate says the library it needs
    is absent, and in `failed` when it ran and raised. Every analyzer
    field below carries a default (`None` or an empty list) precisely so
    a partially-populated report -- one analyzer skipped, one failed,
    the rest present -- is a valid StaticReport and not a construction
    error.
    """
    path: str
    size: int
    sha256: str
    entropy: EntropyReport | None = None
    filetype: FileTypeReport | None = None
    pe: PEStaticReport | None = None
    yara: list[YaraHit] = field(default_factory=list)
    #: Non-empty when the YARA pass stopped before considering every rule
    #: file under the rules directory -- the aggregate wall-clock budget or
    #: the rule-file count cap was hit. See static/yara_scan.py and
    #: branch-review.md I5: a partial scan must never be reported as a
    #: complete one.
    yara_note: str = ""
    strings: StringsReport | None = None
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


@dataclass
class Report:
    indicator: str
    generated_at: str
    vt: VTReport
    otx: OTXReport
    ips: dict[str, IPReport]
    hosts: list[CensysHost]
    whois: list[WhoisRecord]
    source_file: str | None = None
    #: None when static analysis was skipped (--no-static, a bare hash
    #: argument with no file, or an analyzer-fan-out failure) -- never a
    #: half-built StaticReport standing in for "we didn't run it".
    static: StaticReport | None = None
    #: Phase 4 sources. Each is None (or empty) when that source never ran
    #: -- the same rule the rest of this file follows, so a consumer can
    #: tell "the source had nothing" from "this tool never asked it".
    bazaar: BazaarReport | None = None
    threatfox: ThreatFoxReport | None = None
    certs: CertReport | None = None
    #: Keyed by IP, the same way `ips` is: these fan out over the contacted
    #: IPs rather than describing the sample itself.
    shodan: dict[str, ShodanReport] = field(default_factory=dict)
    greynoise: dict[str, GreyNoiseReport] = field(default_factory=dict)
    #: CVEs on contacted IPs that CISA has confirmed are exploited in the
    #: wild. Empty both when nothing matched and when there was nothing to
    #: match -- the catalog is only fetched when Shodan reported CVEs.
    kev: list[KEVEntry] = field(default_factory=list)
