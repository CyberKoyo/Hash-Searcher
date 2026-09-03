import dataclasses

from hash_searcher.models import (
    CensysHost, IPReport, OTXReport, Report, SigmaRule, VTReport, WhoisRecord,
)


def test_sigma_rule_is_frozen():
    rule = SigmaRule(title="t", description="d", level="high")
    with __import__("pytest").raises(dataclasses.FrozenInstanceError):
        rule.level = "low"


def test_vt_report_defaults_to_empty_collections():
    vt = VTReport(found=False)
    assert vt.sigma == [] and vt.contacted_ips == [] and vt.contacted_domains == []


def test_report_holds_every_section():
    """It constructs all eight fields, so it should assert all eight. IPReport,
    CensysHost, and WhoisRecord had no field-level assertions anywhere."""
    report = Report(
        indicator="abc", generated_at="2026-08-23 00:00:00",
        vt=VTReport(found=True), otx=OTXReport(recorded_instances=0),
        ips={"198.51.100.10": IPReport(ip="198.51.100.10", confidence=90, reports=2,
                                       hostnames=["h.example"], domain="example")},
        hosts=[CensysHost(ip="198.51.100.10", org="Example AS", asn=64496,
                          country="NL", ports=[80], hostnames=["h.example"],
                          new_hostnames=["new.example"])],
        whois=[WhoisRecord(domain="bad.example", created="2020-01-01",
                           expires="2027-01-01", registrar="R")],
        source_file="sample.bin",
    )
    assert report.indicator == "abc"
    assert report.generated_at == "2026-08-23 00:00:00"
    assert report.source_file == "sample.bin"
    assert report.vt.found is True
    assert report.otx.recorded_instances == 0

    ip = report.ips["198.51.100.10"]
    assert (ip.ip, ip.confidence, ip.reports) == ("198.51.100.10", 90, 2)
    assert ip.hostnames == ["h.example"] and ip.domain == "example"

    host = report.hosts[0]
    assert (host.ip, host.org, host.asn, host.country) == \
        ("198.51.100.10", "Example AS", 64496, "NL")
    assert host.ports == [80] and host.new_hostnames == ["new.example"]
    assert host.error is None

    record = report.whois[0]
    assert (record.domain, record.created, record.expires, record.registrar) == \
        ("bad.example", "2020-01-01", "2027-01-01", "R")
    assert record.error is None


def test_sigma_by_level_partitions_rules():
    vt = VTReport(found=True, sigma=[
        SigmaRule("a", "d", "high"),
        SigmaRule("b", "d", "low"),
        SigmaRule("c", "d", "high"),
    ])
    assert [r.title for r in vt.by_level("high")] == ["a", "c"]
    assert [r.title for r in vt.by_level("medium")] == []


def test_as_count_takes_a_number_and_refuses_anything_else():
    """The coercion every payload-populated int field now goes through.

    Hardcoded expectations, one per input shape. A JSON number can arrive as
    a float, so a finite float is a count; bool is an int in Python and is
    not one here, because {"malicious": true} is not a verdict tally; NaN and
    the infinities are floats that are not counts either.

    THE NEGATIVE CASES CHANGED IN ROUND 2, deliberately, and this docstring
    says so rather than the assertion being quietly edited. Round 1 pinned
    `as_count(-3) == -3`, carrying a negative through on the grounds that it
    is a number. It is a number and it is not a COUNT, which is the property
    the function's own docstring claims to enforce ("a value that is not a
    count is not a count, whether it is missing or unusable"), and the
    consequence was measured: scoring.py::_detection_signal tests
    `detection.malicious == 0` first, so a negative takes neither the zero
    path nor an honest non-zero one, and a VT payload of five -5 buckets
    scored `ratio='-5/-25' verdict=SUSPICIOUS score=20`.

    `floor=None` is the opt-out and it is not decorative: W_SIGNED is -20 and
    W_INTERNET_NOISE is -10, so Signal.points and Verdict.score are signed by
    design and a blanket clamp would have deleted the only two signals in the
    tree that argue AGAINST a verdict. Both halves are asserted below.
    """
    from hash_searcher.models import as_count

    assert as_count(7) == 7
    assert as_count(0) == 0
    assert as_count(-3) == 0
    assert as_count(-3.9) == 0
    assert as_count(-3, floor=None) == -3
    assert as_count(-3.9, floor=None) == -3
    assert as_count(7, floor=None) == 7
    assert as_count(7.9) == 7
    assert as_count(True) == 0
    assert as_count(False) == 0
    assert as_count("<script>") == 0
    assert as_count("7") == 0
    assert as_count(None) == 0
    assert as_count([1, 2]) == 0
    assert as_count({"a": 1}) == 0
    assert as_count(float("nan")) == 0
    assert as_count(float("inf")) == 0
    assert as_count(float("-inf")) == 0
    assert as_count("<script>", 5) == 5


#: Every field in models.py that a payload can reach and that is NOT put at
#: its declared type on construction, with the reason. Exact set equality
#: below, so a new opt-out reddens here and has to be justified in this dict
#: rather than merged on the strength of nobody noticing.
#:
#: Round 1 asserted this list in a test DOCSTRING -- "CensysHost.asn and
#: PEInfo.entry_point are the only other numbers an extractor takes off a
#: payload with no type check" -- and it was false: CensysHost.ports, two
#: lines below the asn that test read, was a third. A docstring cannot be
#: enumerated by anything. This dict is derived from the annotations by the
#: test below, so it cannot drift from the source the way a sentence can.
UNCOERCED_PAYLOAD_FIELDS = {
    ("CensysHost", "asn"):
        "int | None -- Censys returns an integer ASN, but coercing would "
        "DELETE data on the day it returns 'AS15169'. Never enters "
        "arithmetic or an ordering comparison; reaches output through str() "
        "and asdict only.",
    ("PEInfo", "entry_point"):
        "int | None -- same shape and the same argument: VT's entry_point is "
        "an address, it is only ever interpolated, and a hex string would be "
        "information rather than a crash.",
    ("OTXReport", "recorded_instances"):
        "int | str -- declared to hold both because it genuinely does: OTX's "
        "count when OTX reported one, else the literal substitute string "
        "'N/A' or 'N/A, No recorded instances' that analysis/otx.py puts "
        "there. There is no coercion that keeps both.",
}

#: The two int fields that legitimately admit a negative, so as_count's floor
#: is switched off for them. scoring.py's W_SIGNED is -20 (a valid signature
#: is evidence AGAINST) and W_INTERNET_NOISE is -10; Verdict.score sums them.
SIGNED_FIELDS = {("Signal", "points"), ("Verdict", "score")}

#: One hostile value per declared annotation, and what the declaration must
#: turn it into. Literal, not computed from the coercion functions.
_HOSTILE = {
    "int": ("<script>", 0),
    "list[int]": (["8080/tcp", 443, None, True, -1], [443]),
    "str": (12345, "12345"),
    "list[str]": ([1, None], ["1", "None"]),
}


def _models_dataclasses():
    from hash_searcher import models
    return [obj for obj in vars(models).values()
            if dataclasses.is_dataclass(obj) and isinstance(obj, type)
            and obj.__module__ == "hash_searcher.models"]


def _kind(annotation):
    """The declared annotation, as one of _HOSTILE's keys, or None."""
    import types
    import typing
    if annotation is int:
        return "int"
    if annotation is str:
        return "str"
    if annotation == list[int]:
        return "list[int]"
    if annotation == list[str]:
        return "list[str]"
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        if set(typing.get_args(annotation)) == {str, type(None)}:
            return "str"
    return None


def test_every_models_field_holds_the_type_it_declares():
    """The invariant, read out of models.py rather than out of a call site.

    This is the test that replaces "nine extractors remembered to call
    as_count". It does not name a single class: it walks every dataclass the
    module defines, builds it with a hostile value in every field whose
    annotation this repo coerces, and asserts the declaration held. A
    dataclass added later, or a field added to an existing one, is covered
    the moment it exists -- which is precisely what the tenth call site
    (CensysHost.ports) was not.

    It also refuses to be vacuous: the count of fields it actually exercised
    is asserted against a floor, so an annotation change that makes _kind
    return None everywhere reddens instead of passing over an empty loop.
    """
    exercised = 0
    for cls in _models_dataclasses():
        kwargs, expected = {}, {}
        for spec in dataclasses.fields(cls):
            kind = _kind(spec.type)
            if kind is None:
                # Not coerced. Give it something valid so the class can be
                # built at all; what it holds is not this test's subject.
                if spec.default is not dataclasses.MISSING:
                    continue
                if spec.default_factory is not dataclasses.MISSING:
                    continue
                kwargs[spec.name] = None
                continue
            hostile, want = _HOSTILE[kind]
            kwargs[spec.name] = hostile
            expected[spec.name] = want

        instance = cls(**kwargs)
        for name, want in expected.items():
            exercised += 1
            declared = [f.type for f in dataclasses.fields(cls)
                        if f.name == name][0]
            assert getattr(instance, name) == want, (
                f"{cls.__name__}.{name} declares {declared} but holds "
                f"{getattr(instance, name)!r} after construction")

    assert exercised >= 90, (
        f"only {exercised} fields exercised; the enumeration has stopped "
        f"seeing the module it is checking")


def test_the_fields_a_payload_reaches_uncoerced_are_exactly_the_declared_opt_outs():
    """The exclusion list, derived rather than asserted in prose.

    Every field on every models.py dataclass is either coerced to its
    declared type (the test above) or is one of these, and the ANNOTATION is
    what says which. `int | None` and `int | str` are not accidents of typing
    style here; they are the opt-out marker, and writing one is the only way
    to keep a provider value verbatim.

    Restricted to the fields a provider payload can actually reach, which is
    the claim round 1 got wrong. A `float`, a `bool`, a nested dataclass or a
    `dict[...]` field is not a number an extractor takes off a payload and so
    is not on this list; those are enumerated in the round-2 report's R1
    table with the writer of each.
    """
    numeric_opt_outs = set()
    for cls in _models_dataclasses():
        for spec in dataclasses.fields(cls):
            if _kind(spec.type) is not None:
                continue
            if "int" in str(spec.type):
                numeric_opt_outs.add((cls.__name__, spec.name))

    assert numeric_opt_outs == set(UNCOERCED_PAYLOAD_FIELDS), (
        f"the set of numbers a payload reaches uncoerced changed: "
        f"new {sorted(numeric_opt_outs - set(UNCOERCED_PAYLOAD_FIELDS))}, "
        f"gone {sorted(set(UNCOERCED_PAYLOAD_FIELDS) - numeric_opt_outs)}")


def test_only_the_two_scoring_fields_carry_a_negative():
    """The floor's opt-out list, enumerated the same way.

    A negative detection tally is not a tally; a negative signal weight is
    the whole point of W_SIGNED. Both are int fields and nothing but this
    distinguishes them, so it is asserted rather than described.
    """
    signed, clamped = set(), set()
    for cls in _models_dataclasses():
        for spec in dataclasses.fields(cls):
            if spec.type is not int:
                continue
            instance = cls(**{f.name: (-5 if f.name == spec.name else None)
                              for f in dataclasses.fields(cls)
                              if f.name == spec.name
                              or (f.default is dataclasses.MISSING
                                  and f.default_factory is dataclasses.MISSING)})
            got = getattr(instance, spec.name)
            (signed if got == -5 else clamped).add((cls.__name__, spec.name))

    assert signed == SIGNED_FIELDS, f"signed int fields changed: {sorted(signed)}"
    assert len(clamped) >= 10, f"only {len(clamped)} clamped int fields found"
