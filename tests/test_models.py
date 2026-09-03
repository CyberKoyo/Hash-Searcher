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

class _DeclaredDefault:
    """Stands for "this field's own declared default" in _HOSTILE below.

    A bare `str` field's honest nothing is not one value for every field:
    it is "N/A" for CensysHost.country, "" for FileTypeReport.note and
    str() for a field that declares no default at all. So the expectation
    is read off the dataclass FIELD -- the declaration in models.py's class
    body -- rather than off models.as_declared_text. That still reddens if
    the coercion returns None, "" or the string "None" for a field whose
    class body says "N/A". What it cannot catch alone is _declared_nothing
    misreading a default, which is why
    test_a_null_where_a_str_is_declared_becomes_the_declared_nothing pins
    five specific fields against five hardcoded literals.
    """

    def __repr__(self):
        return "<this field's own declared default>"


DECLARED_DEFAULT = _DeclaredDefault()

#: Hostile values per declared annotation, and what the declaration must
#: turn each into. Literal, not computed from the coercion functions.
#:
#: EVERY annotation carries a None case. Bare `str` additionally carries
#: every JSON scalar/container shape that Python's str() would otherwise
#: turn into an invented provider claim.
_HOSTILE = {
    "int": (("<script>", 0), (None, 0)),
    "list[int]": ((["8080/tcp", 443, None, True, -1], [443]), (None, [])),
    "str": ((False, DECLARED_DEFAULT), (0, DECLARED_DEFAULT),
            (["not text"], DECLARED_DEFAULT),
            ({"not": "text"}, DECLARED_DEFAULT),
            (None, DECLARED_DEFAULT)),
    # A wrong type is absence, not a Python spelling. Unlike a bare `str`,
    # this annotation CAN say "no answer", so the honest answer for a value
    # that is not a string is the None the union already declares -- the
    # same rule as bare `str`, resolved to what this declaration can hold.
    "str | None": ((12345, None), (False, None), (None, None)),
    # Pinned literally, because this is the pair round 2 got wrong in the
    # other direction: it asserted ([1, None], ["1", "None"]) and so
    # certified the fabrication. A member that is not a string is dropped,
    # and the surviving string proves the list is not simply emptied.
    "list[str]": ((["trojan", 1, None, {"a": 1}], ["trojan"]), (None, [])),
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
            return "str | None"
    return None


def _wanted(want, spec):
    """Resolve DECLARED_DEFAULT against the field's own declaration."""
    if want is not DECLARED_DEFAULT:
        return want
    if spec.default is not dataclasses.MISSING:
        return spec.default
    if spec.default_factory is not dataclasses.MISSING:
        return spec.default_factory()
    return ""


def test_every_models_field_holds_the_type_it_declares():
    """The invariant, read out of models.py rather than out of a call site.

    This is the test that replaces "nine extractors remembered to call
    as_count". It does not name a single class: it walks every dataclass the
    module defines, builds it with a hostile value in every field whose
    annotation this repo coerces, and asserts the declaration held. A
    dataclass added later, or a field added to an existing one, is covered
    the moment it exists -- which is precisely what the tenth call site
    (CensysHost.ports) was not.

    Every annotation now carries more than one hostile value, None among
    them, and the whole set is run against every field -- see _HOSTILE for
    why a fixture of one value per annotation was the hole rather than a
    detail of it.

    It also refuses to be vacuous: the count of fields it actually exercised
    is asserted against a floor, so an annotation change that makes _kind
    return None everywhere reddens instead of passing over an empty loop.
    """
    exercised = 0
    rounds = max(len(pairs) for pairs in _HOSTILE.values())
    for case in range(rounds):
        for cls in _models_dataclasses():
            kwargs, expected = {}, {}
            for spec in dataclasses.fields(cls):
                kind = _kind(spec.type)
                if kind is None:
                    # Not coerced. Give it something valid so the class can
                    # be built at all; what it holds is not this test's
                    # subject.
                    if spec.default is not dataclasses.MISSING:
                        continue
                    if spec.default_factory is not dataclasses.MISSING:
                        continue
                    kwargs[spec.name] = None
                    continue
                pairs = _HOSTILE[kind]
                hostile, want = pairs[min(case, len(pairs) - 1)]
                kwargs[spec.name] = hostile
                expected[spec.name] = _wanted(want, spec)

            instance = cls(**kwargs)
            for name, want in expected.items():
                exercised += 1
                declared = [f.type for f in dataclasses.fields(cls)
                            if f.name == name][0]
                assert getattr(instance, name) == want, (
                    f"{cls.__name__}.{name} declares {declared} but holds "
                    f"{getattr(instance, name)!r} after construction with "
                    f"{kwargs[name]!r}")

    assert exercised >= 190, (
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


def test_a_null_where_a_str_is_declared_becomes_the_declared_nothing():
    """The counter-example the round-2 fixture could not reach, pinned literally.

    Round 2's models.py passed None through for a bare `str` field on the
    written justification that "a `str` field holding None is this repo's
    own bug rather than provider data". It is not. `.get(key, default)`
    fires its default on an ABSENT key and on nothing else, so a provider
    `null` walks past `result.get("ip", "N/A")` and lands in a field
    declared `str` -- measured, on the surfaces an analyst reads: the TTY
    printed `Label:      None`, the JSON emitted `"label": null` under a
    key whose declared type is string, and a Sigma rule whose level was
    null disappeared from every by_level bucket.

    The expectations here are five hardcoded literals rather than anything
    derived, because the test above derives its expectation from the same
    declaration models._declared_nothing reads. These are what keeps that
    from being circular: "N/A" and "default" are written out, so a
    coercion that answered "" everywhere would redden here even though it
    agreed with itself.
    """
    from hash_searcher.models import CensysHost, SourceResult, YaraHit

    # A field with no declared default falls back to str(), exactly as
    # as_count's default is int().
    assert CensysHost(ip=None).ip == ""
    # A field WITH one gets its own, not a blanket empty string.
    assert CensysHost(ip="198.51.100.10", country=None).country == "N/A"
    assert YaraHit(rule=None, namespace=None).namespace == "default"
    assert YaraHit(rule=None, namespace=None).rule == ""
    # `str | None` is the opt-out, and it is the ANNOTATION that opts out:
    # None is one of the two things the union declares, so it survives.
    assert SourceResult(error=None).error is None
    # ...and a value that is neither becomes the None it declares, rather
    # than a provider claim Python spelled: `str(False)` is "False".
    assert SourceResult(error=12345).error is None
    assert SourceResult(error=False).error is None


def test_a_wrong_type_where_str_is_declared_becomes_the_declared_nothing():
    """Wrong JSON types are absence, never Python-spelled provider text."""
    from hash_searcher.models import CensysHost, SigmaRule

    rule = SigmaRule(title=False, description=0, level=["high"])
    host = CensysHost(ip={"address": "198.51.100.10"}, country=False)

    assert (rule.title, rule.description, rule.level) == ("", "", "")
    assert host.ip == ""
    assert host.country == "N/A"


def test_the_declaration_holds_after_assignment_and_not_only_at_construction():
    """Thirteen of the module's 33 dataclasses are mutable.

    "A field holds the type it declares" was true only of a field nobody
    had assigned to since it was built, which is a smaller claim than the
    sentence makes. Nothing in src/ assigns to a coercible field today, so
    this breaks nothing -- but the invariant should not depend on that
    staying true, and re-measuring it is not something a future reader
    should have to do.

    Enumerated rather than named, the same way the construction test is:
    every mutable dataclass, every coercible field on it.
    """
    checked = 0
    for cls in _models_dataclasses():
        if cls.__dataclass_params__.frozen:
            continue
        kwargs = {}
        for spec in dataclasses.fields(cls):
            if (spec.default is dataclasses.MISSING
                    and spec.default_factory is dataclasses.MISSING):
                kind = _kind(spec.type)
                pairs = _HOSTILE.get(kind)
                kwargs[spec.name] = pairs[0][0] if pairs else None
        instance = cls(**kwargs)
        for spec in dataclasses.fields(cls):
            kind = _kind(spec.type)
            if kind is None:
                continue
            for hostile, want in _HOSTILE[kind]:
                setattr(instance, spec.name, hostile)
                checked += 1
                assert getattr(instance, spec.name) == _wanted(want, spec), (
                    f"{cls.__name__}.{spec.name} declares {spec.type} but "
                    f"holds {getattr(instance, spec.name)!r} after being "
                    f"assigned {hostile!r}")

    assert checked >= 60, (
        f"only {checked} assignments checked; the enumeration has stopped "
        f"seeing the mutable classes it is about")


def test_coerced_refuses_a_class_it_can_say_nothing_true_about():
    """@coerced's two import-time guards, and the one _declared_nothing adds.

    Both of the original two survived round 2's mutation run untouched
    (mutants M-F and M-G), and `coerced()`'s own docstring rests an
    argument on the first: "passing a name that is not an `int` field on
    this class raises at import, so a renamed field cannot silently leave a
    floor on". Nothing checked that it still does -- and it did not, quite:
    the check was against every COERCIBLE field, so `signed=("a_str_field",)`
    passed silently and left the sentence false. It is against the int
    fields now, and asserted here.
    """
    import pytest

    from hash_searcher.models import coerced

    with pytest.raises(TypeError, match="no int field"):
        @coerced(signed=("nowhere",))
        @dataclasses.dataclass
        class RenamedAway:
            points: int = 0

    with pytest.raises(TypeError, match="no int field"):
        # The half that was missing: a `str` field is coercible but has no
        # floor, so marking it signed says nothing true either.
        @coerced(signed=("label",))
        @dataclasses.dataclass
        class SignedText:
            label: str = ""
            points: int = 0

    with pytest.raises(TypeError, match="no coercible field"):
        @coerced
        @dataclasses.dataclass
        class NothingToCoerce:
            when: float = 0.0

    with pytest.raises(TypeError, match="not one"):
        # A `str` field whose declared default is not a string is a
        # contradiction in the declaration, and as_declared_text would
        # otherwise hand that default out as a str field's value.
        @coerced
        @dataclasses.dataclass
        class LyingDefault:
            label: str = 0


#: Every call to one of models.py's coercion helpers from outside models.py,
#: with the reason it is not a field declaration doing the work.
#:
#: models.py's as_count docstring asserted "no extractor calls this at all
#: any more" while analysis/vt.py imported it and called it one line under
#: eighty. The sentence was in production source, nothing enumerated it, so
#: nothing reddened -- which is the artifact class round 1's CRITICAL was.
#: This dict is what makes the claim checkable instead of asserted.
COERCION_CALLS_OUTSIDE_MODELS = {
    ("analysis/vt.py", "as_count"):
        "an ordering key -- `key=lambda e: -as_count(e.get('count'))` over a "
        "raw VT payload. Correct BECAUSE there is no declaration there to "
        "hang the invariant on: it sorts a list of dicts, it does not "
        "populate a field.",
}


def test_the_coercion_call_sites_outside_models_are_exactly_the_declared_ones():
    """Read from the source, so the docstring above as_count cannot drift.

    Enumerates every import-and-call of a models.py coercion helper across
    src/, because the claim that matters is a completeness one and a
    sentence cannot be enumerated by anything.
    """
    import ast
    import pathlib

    helpers = {"as_count", "as_counts", "as_texts", "as_declared_text"}
    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "hash_searcher"
    assert root.is_dir(), f"{root} is not where hash_searcher lives any more"

    found, scanned = set(), 0
    for path in sorted(root.rglob("*.py")):
        if path.name == "models.py":
            continue
        scanned += 1
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in helpers:
                found.add((str(path.relative_to(root)), node.func.id))

    assert scanned >= 20, (
        f"only {scanned} modules scanned; the walk has stopped seeing the "
        f"package it is checking")
    assert found == set(COERCION_CALLS_OUTSIDE_MODELS), (
        f"the coercion helpers called from outside models.py changed: "
        f"new {sorted(found - set(COERCION_CALLS_OUTSIDE_MODELS))}, gone "
        f"{sorted(set(COERCION_CALLS_OUTSIDE_MODELS) - found)}. models.py's "
        f"as_count docstring describes this set; update both together.")


def test_as_texts_drops_what_is_not_a_string_rather_than_naming_it():
    """The decision, pinned with literals, and the same one as_counts made.

    Round 2 coerced with str(), so `{"tags": ["trojan", null]}` produced a
    tag named `None` on the TTY, in the PDF, and in the JSON report, where
    the commit before it had emitted an honest null. A tag named None, a
    tag named `{'a': 1}` and a tag named `7` are facts about the sample
    that no provider asserted.

    Dropping is what as_counts does with a port it cannot read, for the
    argument as_counts publishes: a scalar must hold something, but a list
    can simply be shorter, and coercing invents a member nobody reported.
    """
    from hash_searcher.models import as_counts, as_texts

    assert as_texts(["trojan", None]) == ["trojan"]
    assert as_texts(["trojan", 7, {"a": 1}, True, ["nested"]]) == ["trojan"]
    assert as_texts([]) == []
    assert as_texts(None) == []
    assert as_texts("trojan") == []          # not a list is not a list of strings
    assert as_texts(["a", "b"]) == ["a", "b"]

    # The two are answering one question the same way now. This is the
    # assertion that reddens if they diverge again.
    assert as_texts([None]) == [] and as_counts([None]) == []


def test_a_null_tag_is_absent_from_the_json_report_rather_than_named_None():
    """The surface the Constraint 3 breach was on.

    `bazaar.tags` is serialized straight out of the dataclass, so what the
    field holds is what the JSON says. Asserted end to end from a provider
    payload rather than on as_texts alone, because the finding was about
    what a consumer reads.
    """
    from hash_searcher.analysis.bazaar import extract_bazaar

    result = extract_bazaar(
        {"query_status": "ok",
         "data": [{"tags": ["trojan", None, {"a": 1}, 7]}]})
    assert result.value.tags == ["trojan"]
    assert "None" not in result.value.tags


def test_as_counts_drops_a_negative_the_way_as_count_floors_one():
    """The floor as_count got a docstring, an opt-out and a test for.

    `if number >= 0:` in as_counts had none of the three for a round, and
    the two functions have to agree: a negative is not a tally and not a
    port, whichever container it arrives in. Literal expectations, so this
    reddens on the floor being removed and on it being widened.

    The asymmetry that remains is deliberate and recorded here as well as
    in the docstring: as_counts has no `floor=None` opt-out because no
    `list[int]` field in the module admits a negative -- both are port
    lists -- while two `int` fields genuinely do. Which fields those are is
    enumerated by test_only_the_two_scoring_fields_carry_a_negative rather
    than described, so a signed list field added later shows up there.
    """
    from hash_searcher.models import as_count, as_counts

    assert as_counts([443, -1, 0, -10 ** 40]) == [443, 0]
    assert as_counts([-5]) == []
    assert as_count(-5) == 0
    assert as_count(-5, floor=None) == -5

    # No list[int] field is signed, so no opt-out exists to be tested.
    signed_list_fields = [
        (cls.__name__, spec.name)
        for cls in _models_dataclasses()
        for spec in dataclasses.fields(cls)
        if spec.type == list[int]
        and cls(**{f.name: ([-5] if f.name == spec.name else None)
                   for f in dataclasses.fields(cls)
                   if f.name == spec.name
                   or (f.default is dataclasses.MISSING
                       and f.default_factory is dataclasses.MISSING)}
                ).__getattribute__(spec.name) == [-5]
    ]
    assert signed_list_fields == [], (
        f"{signed_list_fields} keeps a negative, so as_counts' floor is no "
        f"longer a property of every list[int] field and needs the opt-out "
        f"as_count has")
