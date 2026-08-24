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


@dataclass
class VTReport:
    found: bool
    sigma: list[SigmaRule] = field(default_factory=list)
    contacted_ips: list[str] = field(default_factory=list)
    contacted_domains: list[str] = field(default_factory=list)
    error: str | None = None

    def by_level(self, level: str) -> list[SigmaRule]:
        return [r for r in self.sigma if r.level == level]


@dataclass
class OTXReport:
    recorded_instances: object
    attack_techniques: list[str] = field(default_factory=list)
    error: str | None = None


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
