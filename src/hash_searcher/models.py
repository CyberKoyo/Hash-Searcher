"""Shared dataclasses.

analysis/ produces these, render/ consumes them. Nothing here does I/O or
formatting -- that is the whole point of the split.

What this module does own is the one guarantee the split makes possible: a
field here holds the type it declares. `as_count` used to be a function nine
extractor call sites had to remember to call, and the tenth -- CensysHost.ports
at analysis/censys.py -- was written without anyone noticing, which is what an
invariant maintained by memory always eventually does. `@coerced` moves it into
the type: constructing the dataclass is what makes the declaration true, and a
new extractor cannot get it wrong because there is nothing left for it to do.
"""

import functools
import math
from dataclasses import MISSING, dataclass, field, fields
from types import UnionType
from typing import Generic, TypeVar, Union, get_args, get_origin

T = TypeVar("T")


def as_count(value, default: int = 0, floor: int | None = 0) -> int:
    """A provider-supplied number, or `default` when it is not one.

    Every int field below that an extractor populates from a payload was
    read with a bare `.get(name, 0)`. The 0 covers an ABSENT key and nothing
    else, so a present-but-non-numeric value -- `{"suspicious": "<script>"}`
    -- travelled into an int field and raised the first time anything did
    arithmetic on it: Detection.total sums five of them, and scoring.py
    compares AbuseIPDB's confidence with `max(...)` and `<`. Both raise
    TypeError from provider input, unhandled, on EVERY surface (score, the
    TTY, the PDF and the JSON report), which takes down a run in which every
    provider succeeded.

    Coercing to `default` rather than raising or carrying the string is the
    same bargain the `.get(name, 0)` already made: a value that is not a
    count is not a count, whether it is missing or unusable. json.loads can
    yield a float for a JSON number, so a finite float is a count; `bool` is
    an int in Python and is not one here, because `{"malicious": true}` is
    not a verdict tally.

    `floor` applies that same sentence to a NEGATIVE, which round 1 left
    through: -3 is no more a tally of engines than "<script>" is. It is not
    an academic case. scoring.py::_detection_signal branches on
    `detection.malicious == 0` first, so a negative takes neither the zero
    path nor an honest non-zero one -- `{"malicious": -5}` with matching
    buckets was measured end to end as `ratio='-5/-25' verdict=SUSPICIOUS
    score=20`. `floor=None` is the opt-out, for the two fields in this module
    that are genuinely signed: scoring.py's W_SIGNED is -20 and
    W_INTERNET_NOISE is -10, so Signal.points and the Verdict.score summed
    from them admit a negative by design. A blanket `max(0, ...)` would have
    silently deleted the only two signals in the tree that argue AGAINST a
    verdict.

    Lives in models.py, beside the `malicious: int` declarations it exists
    to make true, rather than in one extractor that the next extractor then
    has to remember about -- the argument A4c made for moving the height fit
    into pdf.py's cell factory. `@coerced` below finishes that argument: no
    extractor calls this to satisfy a DECLARATION any more. One call site
    outside this module survives -- analysis/vt.py sorts VT's popular
    threat names by `-as_count(e.get("count"))` -- and it is correct
    precisely because there is no declaration there to hang the invariant
    on: it is an ordering key over a raw payload, not a field. Round 2's
    version of this sentence said "no extractor calls this at all any
    more", which was false one import away, so the sentence is no longer
    the evidence: tests/test_models.py's
    test_the_coercion_call_sites_outside_models_are_exactly_the_declared_ones
    enumerates them from the source, with a reason recorded per call site,
    and this paragraph has to agree with it.
    """
    if isinstance(value, bool):
        coerced = default
    elif isinstance(value, int):
        coerced = value
    elif isinstance(value, float) and math.isfinite(value):
        coerced = int(value)
    else:
        coerced = default
    return coerced if floor is None else max(floor, coerced)


def as_counts(value) -> list[int]:
    """The counts in a provider-supplied list, for a `list[int]` field.

    DROPS what is not a count rather than coercing it to `as_count`'s
    default, which is the difference between a list field and a scalar one:
    a scalar must hold something and 0 is the honest nothing, while a list
    can simply be shorter. Coercing would invent a port 0 that no scanner
    reported. This is exactly what analysis/shodan.py already did by hand
    with `if isinstance(p, int)`; CensysHost.ports, declared the same
    `list[int]`, did not, and shipped `['8080/tcp', 443]` into a JSON
    document whose schema says these are integers.

    A value that is not a list at all is not a list of counts -- `{"ports":
    443}` yields [], not [443] -- because the field says `list[int]` and
    guessing at a caller's intent is how the shapes below stopped matching
    their declarations in the first place.

    A NEGATIVE member is dropped for the same reason as_count floors one at
    0: -5 is no more a tally or a port number than "<script>" is. That
    sentence went unwritten for a round while as_count's identical floor
    got five lines, an opt-out and a test of its own, which is how a
    reviewer found it by reading `if number >= 0:` rather than by reading
    this.

    There is deliberately NO `floor=None` opt-out to match as_count's.
    as_count needs one because two int fields in this module genuinely
    admit a negative -- scoring.py's W_SIGNED is -20 and W_INTERNET_NOISE
    is -10, so Signal.points and the Verdict.score summed from them argue
    AGAINST a verdict. No `list[int]` field is like that: both of them are
    port lists, and a negative port is not a port. An unused opt-out would
    be machinery that says a field somewhere needs it, and none does.
    test_only_the_two_scoring_fields_carry_a_negative is what enumerates
    which fields admit a negative, so if a signed `list[int]` field is ever
    declared it will be visible there rather than depending on this
    paragraph staying true.
    """
    if not isinstance(value, list):
        return []
    counts = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            continue
        if isinstance(item, float) and not math.isfinite(item):
            continue
        number = int(item)
        if number >= 0:
            counts.append(number)
    return counts


def as_texts(value) -> list[str]:
    """The strings in a provider-supplied list, for a `list[str]` field.

    Same shape rule as as_counts and the SAME coercion: a member that is
    not a string is DROPPED, not turned into one.

    Round 2 wrote str() here instead, on the argument that str() is total
    where int() is not, so nothing need be deleted from the report. What
    that actually produced was `{"tags": ["trojan", null]}` ->
    `["trojan", "None"]` -- a tag named None, and beside it a tag named
    `{'a': 1}` and a tag named `7`. Those are facts about the sample that
    no provider asserted, in a document an analyst pivots from, and they
    reached all three surfaces: the TTY, the PDF, and the JSON report,
    where the commit before that one had emitted an honest null.

    as_counts, five lines above, faces the identical shape problem and
    already published the answer: "a scalar must hold something and 0 is
    the honest nothing, while a list can simply be SHORTER. Coercing would
    invent a port 0 that no scanner reported." Inventing a tag is the same
    act. Two functions in one module giving opposite answers to one
    question, with an argument written under only one of them, is how the
    disagreement went unnoticed for a round.

    The crash this function exists to close is closed either way, and it is
    not in this layer: render/tty.py and render/pdf.py join these lists --
    `', '.join(bazaar.value.tags)`, `', '.join(vt.submission.names)`,
    sixteen sites -- and str.join raises TypeError on a non-string member.
    Measured against `{"data": [{"tags": [1, 2]}]}`: TTY and PDF both
    raised `sequence item 0: expected str instance, int found`, unhandled,
    while the JSON surface printed it happily. Dropping the member closes
    that crash exactly as coercing it did, without asserting anything.
    """
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def as_declared_text(value, nothing: str = "") -> str:
    """A bare `str` field's value, at the type it declares.

    `nothing` is what the field holds when the provider supplied something
    that is not a string, and it is the field's OWN declared default --
    "N/A" for CensysHost.country, "" for FileTypeReport.note, and str()
    for a field that declares no default, exactly as as_count's is int().

    Round 2 passed None straight through here, on a docstring that said "a
    `str` field holding None is this repo's own bug rather than provider
    data". That sentence was false, and measurably so:
    `.get(key, default)` fires its default on an ABSENT key and on nothing
    else, so `{"ip": null}` walked past `result.get("ip", "N/A")` and put
    None in CensysHost.ip, declared `str`. Eight bare-`str` fields are
    reachable that way from a provider payload -- CensysHost.ip,
    ThreatClass.label, SandboxVerdict.sandbox, YaraMatch.rule, all three
    SigmaRule fields, and AttackTechnique.name through the MITRE bundle --
    and the consequences were user-visible, not theoretical: the TTY
    printed `Label:      None`, the JSON emitted `"label": null` under a
    key whose declared type is string, and a Sigma rule whose level was
    null vanished from every by_level bucket.

    The answer is as_count's, one declared type over. A scalar must hold
    SOMETHING -- the as_counts argument that a list can simply be shorter
    is not available to it -- and the honest something is the nothing the
    field itself declares. `str | None` is the opt-out and it is the
    ANNOTATION that opts out, the same way `int | None` opts out of
    as_count: a field that genuinely has no value says so in its type.
    """
    return value if isinstance(value, str) else nothing


def _as_optional_text(value):
    """A `str | None` field's value. None is one of the two it declares.

    The union is the opt-out marker, so unlike as_declared_text above this
    keeps a null verbatim: SourceResult.error, CensysHost.org and the rest
    are declared `str | None` precisely because "no answer" is data there,
    and every consumer that could raise on it -- the str.join sites in
    render/ -- already skips a None with `if x`.

    A value that is NEITHER gets that same None, and this is as_declared_text's
    rule rather than a second one: a wrong type is absence, and absence is
    spelled with whatever the declaration can hold. A bare `str` has only its
    declared default to say that with; this annotation has None itself, which
    is the more honest of the two. What neither may do is answer with a
    provider claim nobody made -- str(False) is "False", and an org named
    False, printed on the terminal, written into JSON and drawn into the PDF
    Censys row, is the same invention `as_texts` was stopped from making one
    declared type over.
    """
    if value is None or isinstance(value, str):
        return value
    return None


def _declared_nothing(spec) -> str:
    """A bare `str` field's own declared default, as as_declared_text's floor.

    Read off the dataclass field rather than chosen here, so the answer for
    a field is written beside the field. A `str` field that declares a
    default which is not a string is a contradiction in the declaration and
    raises at import rather than being papered over at runtime.
    """
    if spec.default is not MISSING:
        nothing = spec.default
    elif spec.default_factory is not MISSING:
        nothing = spec.default_factory()
    else:
        return ""
    if not isinstance(nothing, str):
        raise TypeError(
            f"field {spec.name!r} declares `str` but defaults to "
            f"{nothing!r}, which is not one")
    return nothing


def _text_coercion(nothing: str):
    return lambda value: as_declared_text(value, nothing)


#: field annotation -> the one total coercion for it. A field whose
#: annotation is NOT a key here is opted out, and the annotation IS the
#: opt-out: `int | None` (CensysHost.asn, PEInfo.entry_point) and `int | str`
#: (OTXReport.recorded_instances) are declared as unions precisely because
#: they carry a provider value that is not a plain count -- an `asn` of
#: "AS15169" is data, and coercing it to 0 would delete it. `str | None` is
#: a key here rather than an opt-out for the same reason read the other
#: way: it declares that None is one of the two things the field holds, so
#: the coercion for it keeps a null and the one for a bare `str` does not.
#: That is a property of the source now, not a sentence in a test
#: docstring; round 1's docstring claimed a two-item exclusion list and the
#: third item was two lines from the field it read.
#:
#: Each entry takes the dataclass FIELD and whether it was named `signed`,
#: and returns the one-argument coercion for it -- because two of the four
#: answers depend on the declaration and not only on the annotation: an int
#: field's floor comes from `signed`, and a str field's nothing comes from
#: its own default.
_COERCIONS = {
    "int": lambda spec, signed: (
        lambda value: as_count(value, floor=None if signed else 0)),
    "list[int]": lambda spec, signed: as_counts,
    "str": lambda spec, signed: _text_coercion(_declared_nothing(spec)),
    "str | None": lambda spec, signed: _as_optional_text,
    "list[str]": lambda spec, signed: as_texts,
}


def _declared(annotation) -> str | None:
    """Which coercion an annotation asks for, or None for an opt-out."""
    if annotation is int:
        return "int"
    if annotation is str:
        return "str"
    if annotation == list[int]:
        return "list[int]"
    if annotation == list[str]:
        return "list[str]"
    if get_origin(annotation) in (Union, UnionType):
        if set(get_args(annotation)) == {str, type(None)}:
            return "str | None"
    return None


def coerced(cls=None, *, signed: tuple[str, ...] = ()):
    """Class decorator: after construction, every field holds its declared type.

    The alternative -- and what this branch did for nine rounds -- is a rule
    applied at call sites. `test_the_two_optional_payload_numbers_left_
    uncoerced_are_inert` is the proof that does not work: it asserted an
    exclusion list of two, in a docstring, while the third exclusion sat two
    lines below the field the test read, uncoerced, wrong on the JSON surface
    and crashing on the Censys one.

    The reviewer's objection to doing this was that it would make a hostile
    value unconstructible and so make the pdf escaping untestable. It does
    make `Detection(suspicious="<script>")` impossible -- that is the point --
    but escaping is exercised through `str` fields (test_render_pdf.py:95,
    :141, :346) which no coercion here touches, and rule 1 is pinned from the
    source besides. Nothing was traded away.

    `signed` names the `int` fields that legitimately admit a negative; see
    as_count. Passing a name that is not an `int` field on this class raises
    at import, so a renamed field cannot silently leave a floor on --
    checked against the int fields specifically, not merely against the
    coercible ones, and pinned by
    test_coerced_refuses_a_class_it_can_say_nothing_true_about rather than
    left as this sentence's word for it.

    Applied only to the classes that declare a coercible field -- on any
    other it would be a no-op decoration nobody could justify. What stops the
    next dataclass being forgotten is not this list but
    test_every_models_field_holds_the_type_it_declares, which enumerates the
    module rather than naming classes.
    """
    def decorate(target):
        coercions = []
        integers = set()
        for spec in fields(target):
            kind = _declared(spec.type)
            if kind is None:
                continue
            if kind == "int":
                integers.add(spec.name)
            coercions.append(
                (spec.name, _COERCIONS[kind](spec, spec.name in signed)))
        unknown = set(signed) - integers
        if unknown:
            raise TypeError(
                f"{target.__name__} declares no int field(s) "
                f"{sorted(unknown)} to mark signed")
        if not coercions:
            raise TypeError(
                f"{target.__name__} declares no coercible field; @coerced on "
                f"it says something about the class that is not true")

        # __init__ rather than __post_init__: @dataclass has already run by
        # the time this decorator does (decorators apply bottom-up), and
        # @dataclass decides whether to emit a __post_init__ call while it
        # builds __init__ -- so a __post_init__ installed afterwards is
        # never called. Wrapping __init__ also covers dataclasses.replace().
        built = target.__init__

        @functools.wraps(built)
        def __init__(self, *args, **kwargs):
            built(self, *args, **kwargs)
            for name, coerce in coercions:
                # object.__setattr__ because most of these are frozen; the
                # invariant has to hold for them too.
                object.__setattr__(self, name, coerce(getattr(self, name)))

        target.__init__ = __init__

        # Thirteen of this module's 33 dataclasses are mutable, and until
        # now the invariant held only at construction -- "a field holds the
        # type it declares" was true of a field nobody had assigned to
        # since. Nothing in src/ assigns to a coercible field today (an AST
        # walk finds 8 attribute assignments, none of them here), so this
        # breaks nothing; it means the sentence is now true without that
        # measurement having to be repeated by every future reader.
        if not target.__dataclass_params__.frozen:
            by_name = dict(coercions)

            def __setattr__(self, name, value):
                coerce = by_name.get(name)
                object.__setattr__(
                    self, name, coerce(value) if coerce else value)

            target.__setattr__ = __setattr__
        return target

    return decorate if cls is None else decorate(cls)

@coerced
@dataclass(frozen=True)
class SourceResult(Generic[T]):
    """One shape for every source that can fail: never asked, asked and
    failed, or answered.

    Two states used to share one representation -- `error=None` was true
    both when a source found nothing and when nobody had called it, which is
    why cli.py threaded `raw["bazaar"] is not None` checks by hand and why
    CISA KEV needed two bolted-on `Report` fields (`kev_error`,
    `kev_unchecked`) instead of one honest type. `ok` is the single gate a
    consumer needs: true only when the source ran and came back clean, so a
    signal or a renderer can trust `.value` without checking `.queried` and
    `.error` separately.
    """
    value: T | None = None
    error: str | None = None
    queried: bool = False

    @property
    def ok(self) -> bool:
        return self.queried and self.error is None


@coerced
@dataclass
class KEVReport:
    """CISA KEV's answer for the CVEs observed on contacted hosts.

    `unchecked` is set even when the catalog fetch failed -- it is the one
    field on this branch's `SourceResult` that survives an error, because
    the count of CVEs that went unchecked is itself the fact the CLI and the
    renderers need to report; see analysis/kev.py.
    """
    entries: list["KEVEntry"] = field(default_factory=list)
    unchecked: int = 0


@coerced
@dataclass(frozen=True)
class SigmaRule:
    title: str
    description: str
    level: str


@coerced
@dataclass(frozen=True)
class AttackTechnique:
    id: str
    name: str
    tactic: str | None = None
    url: str | None = None


@coerced
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


@coerced
@dataclass(frozen=True)
class ThreatClass:
    label: str
    family: str | None = None
    categories: list[str] = field(default_factory=list)


@coerced
@dataclass(frozen=True)
class Submission:
    first_seen: str | None = None
    times_submitted: int = 0
    names: list[str] = field(default_factory=list)


@coerced
@dataclass(frozen=True)
class Signature:
    verified: bool = False
    signer: str | None = None
    product: str | None = None


@coerced
@dataclass(frozen=True)
class SandboxVerdict:
    sandbox: str
    category: str
    malware_names: list[str] = field(default_factory=list)


@coerced
@dataclass(frozen=True)
class YaraMatch:
    rule: str
    author: str | None = None
    description: str | None = None


@coerced
@dataclass(frozen=True)
class PEInfo:
    imphash: str | None = None
    entry_point: int | None = None
    sections: int = 0
    compiled: str | None = None


@coerced
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
    #: True when the VT call failed for any reason other than a 404.
    #: found=False alone conflates "no record exists" with "we could not
    #: get an answer" -- unavailable is how a caller tells them apart.
    unavailable: bool = False

    def by_level(self, level: str) -> list[SigmaRule]:
        return [r for r in self.sigma if r.level == level]


@coerced
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


@coerced
@dataclass
class IPReport:
    ip: str
    confidence: int = 0
    reports: int = 0
    hostnames: list[str] = field(default_factory=list)
    domain: str | None = None


@coerced
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


@coerced
@dataclass
class WhoisRecord:
    domain: str
    created: str = "N/A"
    expires: str = "N/A"
    registrar: str = "N/A"
    error: str | None = None


@coerced
@dataclass
class BazaarReport:
    """MalwareBazaar's answer for one hash.

    found=False is a real answer -- the repository has never seen this
    sample. Whether the lookup itself failed lives on the SourceResult that
    wraps this report (see extract_bazaar), not on this dataclass -- a
    result nobody asked for and a clean "not found" used to share the same
    error=None representation, which is the distinction SourceResult exists
    to restore.
    """
    found: bool = False
    family: str | None = None
    tags: list[str] = field(default_factory=list)
    file_type: str | None = None
    first_seen: str | None = None
    yara: list[str] = field(default_factory=list)


@coerced
@dataclass
class ShodanReport:
    """Shodan InternetDB's answer for one IP.

    An all-empty report means Shodan has never scanned the address -- a
    real answer, not a failure. See BazaarReport's docstring: whether the
    lookup itself failed is carried by the wrapping SourceResult.
    """
    ports: list[int] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)


@coerced
@dataclass
class GreyNoiseReport:
    """Whether an IP is internet background noise or was aimed at you."""
    seen: bool = False
    classification: str | None = None
    name: str | None = None
    last_seen: str | None = None


@coerced
@dataclass
class CertReport:
    """Sibling domains from certificate transparency.

    `siblings` is capped at analysis.crtsh.SIBLING_LIMIT for readability;
    `count` is the untruncated total, so a capped list never reads as the
    whole answer.
    """
    siblings: list[str] = field(default_factory=list)
    count: int = 0


@coerced
@dataclass
class ThreatFoxReport:
    """ThreatFox's family attribution for one indicator."""
    found: bool = False
    malware: str | None = None
    confidence: int = 0
    tags: list[str] = field(default_factory=list)


@coerced
@dataclass(frozen=True)
class KEVEntry:
    """One CVE CISA has confirmed is exploited in the wild."""
    cve: str
    vendor: str | None = None
    product: str | None = None
    name: str | None = None
    date_added: str | None = None
    ransomware: bool = False


@coerced(signed=("points",))
@dataclass(frozen=True)
class Signal:
    name: str
    points: int
    detail: str


@coerced(signed=("score",))
@dataclass(frozen=True)
class Verdict:
    level: str
    score: int
    signals: list[Signal] = field(default_factory=list)


@coerced
@dataclass(frozen=True)
class EntropyReport:
    overall: float = 0.0
    packed: bool = False
    note: str = ""


@coerced
@dataclass(frozen=True)
class FileTypeReport:
    detected: str | None = None
    extension: str = ""
    mismatch: bool = False
    note: str = ""


@coerced
@dataclass(frozen=True)
class PESection:
    name: str
    size: int = 0
    entropy: float = 0.0
    executable: bool = False


@coerced
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


@coerced
@dataclass(frozen=True)
class YaraHit:
    rule: str
    namespace: str = "default"
    tags: list[str] = field(default_factory=list)


@coerced
@dataclass(frozen=True)
class IOCSet:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


@coerced
@dataclass(frozen=True)
class StringsReport:
    count: int = 0
    iocs: IOCSet = field(default_factory=IOCSet)


@coerced
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


@coerced
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
    #: Which kind of thing `indicator` is -- one of indicators.KINDS. Defaults
    #: to "hash" because that is what every indicator was until Part B: a
    #: Report built without this field means exactly what it always meant.
    #: The renderers read it so they stop labelling an address "Hash".
    indicator_kind: str = "hash"
    #: None when static analysis was skipped (--no-static, a bare hash
    #: argument with no file, or an analyzer-fan-out failure) -- never a
    #: half-built StaticReport standing in for "we didn't run it".
    static: StaticReport | None = None
    #: Phase 4 sources, each wrapped in a SourceResult: `.queried is False`
    #: when that source never ran, the same rule the rest of this file
    #: follows, so a consumer can tell "the source had nothing" from "this
    #: tool never asked it" without a second field to carry that distinction.
    bazaar: SourceResult[BazaarReport] = field(default_factory=SourceResult)
    threatfox: SourceResult[ThreatFoxReport] = field(default_factory=SourceResult)
    certs: SourceResult[CertReport] = field(default_factory=SourceResult)
    #: Keyed by IP, the same way `ips` is: these fan out over the contacted
    #: IPs rather than describing the sample itself.
    shodan: dict[str, SourceResult[ShodanReport]] = field(default_factory=dict)
    greynoise: dict[str, SourceResult[GreyNoiseReport]] = field(default_factory=dict)
    #: ThreatFox again, but per contacted IP rather than for the sample.
    #: A separate field, not a widening of `threatfox`: that one answers
    #: "what is this sample", this one answers "what is the address it
    #: called", and collapsing them would make a C2 hit on a contacted host
    #: indistinguishable from a hit on the file itself. ThreatFox's dataset
    #: is overwhelmingly C2 addresses, so this is where it usually answers
    #: -- and neither Shodan (exposure) nor GreyNoise (noise-vs-targeted)
    #: names a family.
    threatfox_ips: dict[str, SourceResult[ThreatFoxReport]] = field(default_factory=dict)
    #: CVEs on contacted IPs that CISA has confirmed are exploited in the
    #: wild. `.queried is False` when there was nothing to check -- the
    #: catalog is only fetched when Shodan reported CVEs. On a fetch failure
    #: `.value.unchecked` still carries how many CVEs went unchecked, so the
    #: strongest signal this phase produces is never silently read as
    #: "nothing is known-exploited"; see analysis/kev.py.
    kev: SourceResult[KEVReport] = field(default_factory=SourceResult)
