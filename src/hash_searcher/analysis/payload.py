"""Reading a provider payload as the shape it claims to be.

A payload is JSON someone else wrote, and every module in this package walks
one. `raw.get(key, {})` defends against the key being ABSENT and against
nothing else: `{"services": null}` returns None and `{"services": "none"}`
returns a string, and the next `.get`, iteration or subscript raises --
unhandled, at analysis/ depth, on a run in which every provider answered.
cli.py calls these extractors with no `try` anywhere around them.

`(raw.get(key) or [])` -- the idiom this tree already used at 15 sites --
closes the null half and leaves the rest. A truthy non-list still reaches the
loop, and `{"ports": 443}` measurably still raised `TypeError: 'int' object
is not iterable` at analysis/shodan.py, the very line the reviewer offered as
the model to copy. So the idiom is not the fix; checking the shape is.

The two failures are different and both matter:

  * a CRASH, when the value cannot be used as the container at all;
  * SILENT WRONG OUTPUT, when it can. Iterating a str yields characters and
    iterating a dict yields its keys, so `[s["port"] for s in services if
    "port" in s]` over `["port-scan-result"]` runs `"port" in s` as a
    SUBSTRING test, passes it, and only then raises on the subscript. Over
    `{"port": 1}` it does the same thing to the key. Neither is a shape any
    `or []` would have caught.

A shape fuzz over every extractor -- every JSON path in a well-formed
payload, nine hostile shapes at each -- found 428 crashing combinations
across 58 sites in this package before this module existed. These five
functions are what those 58 sites now go through.

Not in models.py, where as_count lives: as_count is there because it makes a
`malicious: int` DECLARATION true, and these make no declaration true. They
make a TRAVERSAL safe, which is this layer's job.
"""


def as_mapping(value) -> dict:
    """A payload value used as a mapping, or {} when it is not one."""
    return value if isinstance(value, dict) else {}


def as_sequence(value) -> list:
    """A payload value used as a list, or [] when it is not one.

    A str is not a sequence here and neither is a dict, even though both
    iterate. That is the whole point: iterating them succeeds and produces
    characters or keys, which is wrong output nobody notices rather than a
    traceback somebody fixes.
    """
    return value if isinstance(value, list) else []


def as_mappings(value) -> list[dict]:
    """The mappings in a payload list -- the list-of-objects case.

    Every provider in this tree sends at least one: Censys `services`,
    MalwareBazaar and ThreatFox `data`, CISA `vulnerabilities`, OTX
    `pulses`, VT `sigma_analysis_results`, crt.sh's rows, RDAP `events` and
    `entities`. Members that are not mappings are dropped rather than
    coerced, because there is nothing to coerce them to.
    """
    return [item for item in as_sequence(value) if isinstance(item, dict)]


def as_text(value, default: str = "") -> str:
    """A payload value used as a string, or `default` when it is not one.

    For the sites that call a str method on it -- `.strip()`, `.split()`,
    `.upper()` -- or test it for membership in a frozenset, where a non-str
    is a TypeError rather than a mismatch.
    """
    return value if isinstance(value, str) else default


def dig(value, *keys) -> dict:
    """Walk nested mappings, yielding {} the moment one level is not a mapping.

    `raw.get("data", {}).get("attributes", {})` is the shape this replaces,
    and it raises AttributeError on `{"data": null}` -- the single most
    common hostile shape in the fuzz, hit at seven separate sites across
    censys.py, vt.py and attack.py.
    """
    for key in keys:
        value = as_mapping(value).get(key)
    return as_mapping(value)
