"""Every extractor, against every hostile shape at every payload path.

The rule: a value taken off a provider payload and then used as a container
must be checked for being that container. `raw.get(key, default)` returns the
default only when the key is ABSENT, and `(raw.get(key) or [])` -- the idiom
this tree used at 15 sites -- adds only the null case. A truthy non-container
still reaches the loop.

Enumerating the rule instead of the finding is what this file exists for.
Round 1 fixed the sites a review named; the reviewer then named four more; a
mechanical sweep found 58, of which the reviewer's Minor E had named 7. So
this does not enumerate sites at all -- it enumerates PAYLOAD SHAPES and lets
the extractors say which ones they cannot survive. A site added later is
covered without anyone adding a row.

cli.py:170-195 calls these extractors with no try/except anywhere around
them, so every one of these was a traceback on a run in which every single
provider answered successfully.
"""

import copy

from ioc_inquest.analysis.attack import (
    resolve, technique_ids_from_otx, technique_ids_from_vt)
from ioc_inquest.analysis.bazaar import extract_bazaar
from ioc_inquest.analysis.censys import extract_hosts
from ioc_inquest.analysis.crtsh import extract_crtsh, merge_crtsh
from ioc_inquest.analysis.greynoise import extract_greynoise
from ioc_inquest.analysis.ipdb import extract_ips
from ioc_inquest.analysis.kev import known_exploited
from ioc_inquest.analysis.otx import extract_otx
from ioc_inquest.analysis.shodan import extract_shodan
from ioc_inquest.analysis.threatfox import extract_threatfox
from ioc_inquest.analysis.vt import extract_vt
from ioc_inquest.analysis.whois import extract_whois

#: One hostile value per JSON shape a provider can actually send, plus the
#: three numeric edges. Every one of these was measured against HEAD before
#: the fix and took at least one extractor down.
#:
#: "list-of-str" and "dict" are the two that matter most and are the least
#: obvious: `"port" in s` over a STRING is a substring test that passes, and
#: iterating a dict yields its keys, which are strings too. Both reach the
#: subscript and only then raise.
HOSTILE_SHAPES = [
    ("null", None),
    ("str", "port-scan-result"),
    ("int", 7),
    ("bool", True),
    ("empty-list", []),
    ("empty-dict", {}),
    ("list-of-str", ["port"]),
    ("list-of-int", [1]),
    ("dict", {"port": 1}),
    ("negative", -5),
    ("huge", 10 ** 40),
    ("markup", "<b>unclosed"),
    # json.loads produces a float for any JSON number with a point or an
    # exponent, and as_count and vt._epoch_date both carry a dedicated
    # math.isfinite branch written for exactly these -- branches whose only
    # guard was a unit test, never this sweep. NaN and the infinities are
    # not standard JSON but every provider in this tree is read with
    # json.loads, which accepts NaN, Infinity and -Infinity by default.
    ("float", 3.5),
    ("nan", float("nan")),
    ("inf", float("inf")),
    ("-inf", float("-inf")),
]

VT_PAYLOAD = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 2,
                            "undetected": 4, "timeout": 0},
    "popular_threat_classification": {
        "suggested_threat_label": "trojan.x",
        "popular_threat_name": [{"value": "emotet", "count": 5}],
        "popular_threat_category": [{"value": "trojan", "count": 3}]},
    "first_submission_date": 1600000000, "times_submitted": 9,
    "names": ["a.exe"],
    "signature_info": {"verified": "Signed file, verified signature",
                       "signers": "Contoso; Root", "product": "P"},
    "sandbox_verdicts": {"s1": {"sandbox_name": "s1", "category": "malicious",
                                "malware_names": ["m"]}},
    "crowdsourced_yara_results": [{"rule_name": "r", "author": "a",
                                   "description": "d"}],
    "pe_info": {"imphash": "h", "entry_point": 4096, "sections": [{}],
                "timestamp": 1600000000},
    "sigma_analysis_results": [{"rule_title": "t", "rule_description": "d",
                                "rule_level": "high"}],
    "behaviour_mitre_trees": {"s1": {"tactics": [
        {"techniques": [{"id": "T1055"}]}]}}},
    "relationships": {"contacted_ips": {"data": [{"id": "198.51.100.10"}]},
                      "contacted_domains": {"data": [{"id": "e.com"}]}}}}

OTX_PAYLOAD = {"pulse_info": {"count": 4, "pulses": [
    {"attack_ids": [{"id": "T1055", "display_name": "Process Injection"}]}]}}

IPDB_PAYLOAD = {"data": {"ipAddress": "198.51.100.10",
                         "hostnames": ["h.example"], "domain": "example.com",
                         "abuseConfidenceScore": 40, "reports": 3}}

CENSYS_PAYLOAD = {"result": {"resource": {
    "ip": "198.51.100.10",
    "autonomous_system": {"name": "AS", "asn": 64512, "country_code": "US"},
    "dns": {"reverse_dns": {"names": ["h.example"]}},
    "services": [{"port": 443}]}}}

RDAP_PAYLOAD = {"domain": "example.com",
                "events": [{"eventAction": "registration",
                            "eventDate": "2020-01-01T00:00:00Z"}],
                "entities": [{"roles": ["registrar"],
                              "vcardArray": ["vcard",
                                             [["fn", {}, "text", "Reg"]]]}]}

BAZAAR_PAYLOAD = {"query_status": "ok", "data": [
    {"signature": "Emotet", "tags": ["t"], "file_type": "exe",
     "first_seen": "2020-01-01 00:00:00", "yara_rules": [{"rule_name": "r"}]}]}

THREATFOX_PAYLOAD = {"query_status": "ok", "data": [
    {"malware_printable": "Emotet", "confidence_level": 75, "tags": ["t"]}]}

SHODAN_PAYLOAD = {"ports": [443], "cpes": ["c"], "vulns": ["CVE-2021-1"],
                  "hostnames": ["h"]}

GREYNOISE_PAYLOAD = {"noise": True, "classification": "malicious", "name": "n",
                     "last_seen": "2020-01-01"}

KEV_PAYLOAD = {"vulnerabilities": [
    {"cveID": "CVE-2021-1", "vendorProject": "v", "product": "p",
     "vulnerabilityName": "n", "dateAdded": "2020-01-01",
     "knownRansomwareCampaignUse": "Known"}]}

CRTSH_PAYLOAD = [{"name_value": "a.example.com\nb.example.com"}]

#: Every extractor entry point in analysis/, with a well-formed payload for
#: it. Fourteen, which is every public function in the package that takes a
#: payload -- the two attack.py id-harvesters and resolve() included, because
#: they walk VT and OTX payloads too and were three of the 58 crash sites.
EXTRACTORS = [
    ("extract_vt", VT_PAYLOAD, lambda p: extract_vt(p)),
    ("extract_otx", OTX_PAYLOAD, lambda p: extract_otx(p)),
    # The four list-taking extractors are given the LIST as their payload,
    # not an element the harness then wraps. `lambda p: extract_ips([p])`
    # meant the substitution at the <root> path replaced the element and
    # never the argument, so the sweep could not build extract_ips(7) --
    # and reverting analysis/ipdb.py's as_sequence to the `or []` idiom
    # this round exists to eliminate left the suite fully green (round 2's
    # surviving mutant M-K). The payload is the argument now, so _paths'
    # own enumeration reaches the outermost container without anything
    # here having to name it.
    ("extract_ips", [IPDB_PAYLOAD], lambda p: extract_ips(p)),
    ("extract_hosts", [CENSYS_PAYLOAD], lambda p: extract_hosts(p, {})),
    ("extract_whois", [RDAP_PAYLOAD], lambda p: extract_whois(p)),
    ("extract_bazaar", BAZAAR_PAYLOAD, lambda p: extract_bazaar(p)),
    ("extract_threatfox", THREATFOX_PAYLOAD, lambda p: extract_threatfox(p)),
    ("extract_shodan", SHODAN_PAYLOAD, lambda p: extract_shodan(p)),
    ("extract_greynoise", GREYNOISE_PAYLOAD, lambda p: extract_greynoise(p)),
    ("extract_crtsh", CRTSH_PAYLOAD, lambda p: extract_crtsh(p)),
    ("merge_crtsh", [CRTSH_PAYLOAD], lambda p: merge_crtsh(p)),
    ("known_exploited", KEV_PAYLOAD,
     lambda p: known_exploited(["CVE-2021-1"], p)),
    ("technique_ids_from_vt", VT_PAYLOAD, lambda p: technique_ids_from_vt(p)),
    ("technique_ids_from_otx", OTX_PAYLOAD,
     lambda p: resolve(technique_ids_from_otx(p))),
]


def _paths(obj, prefix=()):
    """Every path into a JSON document, the document itself included."""
    yield prefix
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from _paths(value, prefix + (key,))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _paths(value, prefix + (index,))


def _replaced(document, path, value):
    document = copy.deepcopy(document)
    if not path:
        return value
    cursor = document
    for step in path[:-1]:
        cursor = cursor[step]
    cursor[path[-1]] = value
    return document


def test_no_payload_shape_takes_an_extractor_down():
    """The sweep. 3872 (extractor, path, shape) combinations.

    Measured against the commit before this one: **428 of these raised**,
    across **58 distinct source sites** in analysis/. The reviewer's Minor E
    reported 7 of the 58 and the CRITICAL was an eighth; the other 50 were
    never reported by anyone, because nobody had enumerated the rule.

    This is deliberately not a list of the 58. A list of sites is exactly the
    artifact that has failed nine times on this branch: it is complete only
    until the next site is written. The enumeration here is over payload
    SHAPES, which do not grow when the code does.

    The count in the first line is a fact about today and the floor below
    is what actually holds; they are stated separately on purpose, because
    a number in a docstring is the kind of claim nothing enumerates. It
    rose from 2856 when the four list-taking extractors started being
    handed their argument rather than an element of it, and when float, NaN
    and the two infinities joined HOSTILE_SHAPES.
    """
    failures = []
    combinations = 0
    for name, payload, call in EXTRACTORS:
        for path in _paths(payload):
            for shape_name, shape in HOSTILE_SHAPES:
                combinations += 1
                try:
                    call(_replaced(payload, path, shape))
                except Exception as exc:                # noqa: BLE001
                    where = ".".join(map(str, path)) or "<the whole payload>"
                    failures.append(
                        f"{name}: {where} = {shape_name} -> "
                        f"{type(exc).__name__}: {exc}")

    assert combinations >= 2000, (
        f"only {combinations} combinations built; the enumeration has stopped "
        f"seeing the payloads it is checking")
    assert failures == [], (
        f"{len(failures)} of {combinations} payload shapes take an extractor "
        f"down, unhandled, on a run where every provider answered:\n  "
        + "\n  ".join(failures[:25]))


def test_the_substring_trap_produces_no_ports_rather_than_a_crash():
    """The exact shape of CRITICAL 1, asserted on its output rather than only
    on its not raising.

    `[s["port"] for s in services if "port" in s]` over a list of STRINGS ran
    `"port" in s` as a substring test, passed it, and raised on the subscript.
    Over a dict it iterated the keys and did the same. Neither is a shape any
    `or []` catches, and both reach CensysHost.ports, declared list[int].
    """
    def ports(services):
        payload = {"result": {"resource": {"ip": "198.51.100.10",
                                           "services": services}}}
        return extract_hosts([payload], {})[1][0].ports

    assert ports([{"port": 443}, {"port": 80}]) == [443, 80]
    assert ports(["port-scan-result"]) == []
    assert ports({"port": 1}) == []
    assert ports(None) == []
    assert ports("ports") == []
    assert ports(443) == []
    # The wrong-OUTPUT half: a string port is not a port. The JSON report
    # declares these integers and a consumer doing `443 in host["ports"]`
    # got a wrong answer rather than an error.
    assert ports([{"port": "8080/tcp"}, {"port": 443}]) == [443]
    assert ports([{"port": True}, {"port": -1}, {"port": 443.0}]) == [443]


def test_an_explicitly_null_field_is_not_the_same_as_an_absent_one():
    """`{"pulses": null}` and `{}` both have to work, and only one of them did.

    This is the sentence as_count's docstring already made about numbers --
    "the 0 covers an ABSENT key and nothing else" -- carried to containers,
    which is the carry round 1 did not make.
    """
    assert extract_otx({"pulse_info": {"pulses": None, "count": 2}}).attack_techniques == []
    assert extract_otx({"pulse_info": None}).recorded_instances == "N/A"
    assert extract_otx({"pulse_info": []}).recorded_instances == "N/A"
    assert extract_shodan({"ports": None, "cpes": None}).value.ports == []
    assert extract_bazaar(
        {"query_status": "ok", "data": None}).value.found is False
    assert known_exploited(
        ["CVE-2021-1"], {"vulnerabilities": None}).value.entries == []
    assert extract_whois([{"domain": "e.com", "events": None,
                           "entities": None}])[0].registrar == "N/A"
    assert extract_hosts([{"result": None}], {})[1][0].ip == "N/A"


def test_a_relationship_id_that_is_not_a_string_is_not_a_contacted_address():
    """The second instance of CRITICAL 1's shape, in `vt.py::relationship_ids`.

    `[entry["id"] for entry in ... if "id" in entry]` had the identical bug to
    the Censys one: over a list of strings, `"id" in entry` is a substring
    test that passes and `entry["id"]` then raises. The container check alone
    closes the crash, because a non-mapping entry no longer reaches the test
    at all -- so this asserts the OTHER half, which the container check does
    not cover: a mapping whose `id` is a number.

    It matters beyond neatness. api/virustotal.py's contacted_ips delegates
    to this function and the result becomes the address list the per-IP
    fan-out queries. `{"id": 123}` used to enter that list, and the round-2
    `list[str]` invariant would then have made it the string "123" -- a
    lookup against an address no provider named.
    """
    from ioc_inquest.analysis.vt import relationship_ids

    def ids(entries):
        return relationship_ids(
            {"data": {"relationships": {"contacted_ips": {"data": entries}}}},
            "contacted_ips")

    assert ids([{"id": "198.51.100.10"}]) == ["198.51.100.10"]
    assert ids(["identifier"]) == []          # the substring trap
    assert ids([{"id": 123}]) == []
    assert ids([{"id": None}, {"id": ["a"]}]) == []
    assert ids({"id": "198.51.100.10"}) == []
