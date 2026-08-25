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

    def by_level(self, level: str) -> list[SigmaRule]:
        return [r for r in self.sigma if r.level == level]


@dataclass
class OTXReport:
    recorded_instances: object
    attack_techniques: list[str] = field(default_factory=list)
    error: str | None = None
    has_pulses: bool = False
    has_pulse_info: bool = False


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


@dataclass
class WhoisRecord:
    domain: str
    created: str = "N/A"
    expires: str = "N/A"
    registrar: str = "N/A"
    error: str | None = None


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
