"""The PDF gained a verdict block and an attribution block in 1e0afe6 with no
test of either. reportlab's Paragraph parses mini-HTML, so a provider string
containing '<' does not render oddly -- it raises, and `-o report.pdf` dies
with a traceback on an otherwise successful run.

build_story() exists so these assertions can be made on the flowables. There
is no PDF text extractor in the dev dependencies, and adding one to assert on
bytes reportlab just compressed would test zlib, not this module.
"""

from reportlab.platypus import Paragraph, Table

from hash_searcher.models import (
    AttackTechnique, Detection, SandboxVerdict, Signature, SigmaRule, Signal,
    ThreatClass, Verdict, YaraMatch,
)
from hash_searcher.render.pdf import _x, build_story, write_pdf
from hash_searcher.render.tty import VT_UNAVAILABLE_NOTE


def _texts(story) -> list[str]:
    """Every string the story carries, Paragraphs and bare table cells alike.
    The verdict signals are Paragraphs inside a Table, so a top-level-only
    walk would miss exactly the block these tests exist for."""
    out = []
    for flowable in story:
        if isinstance(flowable, Paragraph):
            out.append(flowable.text)
        elif isinstance(flowable, Table):
            for row in flowable._cellvalues:
                for cell in row:
                    out.append(cell.text if isinstance(cell, Paragraph) else cell)
    return out


def test_write_pdf_creates_a_pdf(tmp_path, sample_report):
    path = write_pdf(sample_report, str(tmp_path / "out.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_write_pdf_handles_a_report_with_no_ips(tmp_path, sample_report):
    sample_report.ips, sample_report.hosts, sample_report.whois = {}, [], []
    path = write_pdf(sample_report, str(tmp_path / "empty.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_the_pdf_carries_the_verdict_and_every_signal(sample_report):
    verdict = Verdict(level="MALICIOUS", score=65, signals=[
        Signal(name="detection", points=50, detail="60/67 engines flagged this file"),
        Signal(name="signed", points=-20, detail="valid signature from Contoso Ltd"),
    ])
    story = build_story(sample_report, verdict)
    assert "Verdict: MALICIOUS (score 65)" in _texts(story)
    assert "60/67 engines flagged this file" in _texts(story)
    assert "+50" in _texts(story) and "-20" in _texts(story)


def test_a_verdict_with_no_signals_says_so(sample_report):
    story = build_story(sample_report, Verdict(level="CLEAN", score=0, signals=[]))
    assert "No signals fired." in _texts(story)


def test_the_pdf_carries_the_vt_unavailable_caveat_too(tmp_path, sample_report):
    """render_verdict in tty.py already prints this caveat; the PDF builds
    its own verdict block and had no equivalent -- the same renderer
    asymmetry that produced the Phase 4 KEV bug, where a failed fetch read
    as a clean answer on one surface and not the other.

    The error text is a provider value like any other -- it goes through
    _x() -- so this also exercises the crafted-markup path
    test_markup_in_a_provider_string_is_escaped_not_parsed already covers
    for every other field: a stray '<' in VT's own error text must not
    reach doc.build() unescaped, or `-o report.pdf` dies on the last step
    of an otherwise successful run.
    """
    from hash_searcher.models import VTReport

    verdict = Verdict(level="UNKNOWN", score=0, signals=[])
    sample_report.vt = VTReport(found=False, unavailable=True,
                                 error="GetTotal API Error 503")
    texts = _texts(build_story(sample_report, verdict))
    # Pinned against the literal wording, not just re-derived from the same
    # live import -- VT_UNAVAILABLE_NOTE.format(...) alone would recompute
    # its expected value from the very constant under test, so deleting the
    # caveat's second clause would vanish from both sides at once and this
    # assertion would never notice.
    assert VT_UNAVAILABLE_NOTE == (
        "VirusTotal did not answer ({error}) -- this UNKNOWN is not "
        "confirmation that nobody has seen this sample."
    )
    assert (f"Note: {VT_UNAVAILABLE_NOTE.format(error=_x('GetTotal API Error 503'))}"
            in texts)

    sample_report.vt = VTReport(found=False, unavailable=True,
                                 error="Network Error: <script>")
    texts = _texts(build_story(sample_report, verdict))
    assert any("Network Error: &lt;script&gt;" in t for t in texts)
    path = write_pdf(sample_report, str(tmp_path / "vt_unavailable.pdf"), verdict)
    assert open(path, "rb").read(5) == b"%PDF-"


def test_the_pdf_caveat_is_silent_when_the_verdict_is_not_unknown(sample_report):
    from hash_searcher.models import VTReport

    sample_report.vt = VTReport(found=False, unavailable=True,
                                 error="GetTotal API Error 503")
    texts = _texts(build_story(sample_report, Verdict(level="CLEAN", score=0, signals=[])))
    assert not any("VirusTotal did not answer" in t for t in texts)


def test_the_pdf_caveat_is_silent_for_a_genuine_404_at_unknown(sample_report):
    """A 404 is VirusTotal's actual answer: no record. Printing the caveat
    here would put "VirusTotal did not answer" into a filed written report
    for the one case where VT actually did -- the precise falsehood Ruling
    4 was raised to remove, on the surface an analyst archives."""
    from hash_searcher.analysis.vt import extract_vt
    from hash_searcher.api.base_call import make_error

    sample_report.vt = extract_vt(make_error("Hash not found in GetTotal", 404))
    texts = _texts(build_story(sample_report, Verdict(level="UNKNOWN", score=0, signals=[])))
    assert not any("VirusTotal did not answer" in t for t in texts)


def test_the_pdf_carries_the_attribution_block(sample_report):
    sample_report.vt.threat = ThreatClass(label="trojan.emotet", family="emotet")
    sample_report.vt.signature = Signature(verified=False, signer="Contoso Ltd")
    sample_report.vt.sandbox = [SandboxVerdict(sandbox="Zenbox", category="malicious")]
    sample_report.vt.yara = [YaraMatch(rule="malw_eicar", author="Marc Rivero")]
    sample_report.vt.techniques = [
        AttackTechnique(id="T1055", name="Process Injection", tactic="defense-evasion")
    ]
    texts = _texts(build_story(sample_report, None))
    assert "Label: trojan.emotet" in texts
    assert "Family: emotet" in texts
    assert "Signature: present but NOT verified (Contoso Ltd)" in texts
    assert "Sandbox: Zenbox says malicious" in texts
    assert "YARA: malw_eicar" in texts
    assert "ATT&amp;CK: T1055 Process Injection (defense-evasion)" in texts


def test_markup_in_a_provider_string_is_escaped_not_parsed(tmp_path, sample_report):
    """A crafted Authenticode signer name or YARA rule name containing '<'
    used to raise out of doc.build. Every value in this test comes from a
    provider payload, which is to say from someone else."""
    sample_report.vt.signature = Signature(verified=True, signer="Contoso <script>")
    sample_report.vt.yara = [YaraMatch(rule="rule<A>", author="x")]
    sample_report.vt.threat = ThreatClass(label="trojan.<b>x</b>", family="x&y")
    sample_report.vt.sigma = [SigmaRule("<title>", "desc & more", "high")]
    verdict = Verdict(level="MALICIOUS", score=50, signals=[
        Signal(name="yara", points=10, detail="crowdsourced YARA matched: rule<A>"),
    ])

    texts = _texts(build_story(sample_report, verdict))
    assert "crowdsourced YARA matched: rule&lt;A&gt;" in texts
    assert "YARA: rule&lt;A&gt;" in texts
    assert "Signature: verified (Contoso &lt;script&gt;)" in texts
    assert "Label: trojan.&lt;b&gt;x&lt;/b&gt;" in texts
    assert "Family: x&amp;y" in texts
    assert "<b>&lt;title&gt;</b>: desc &amp; more" in texts, (
        "the <b> around the title is this module's own markup and must survive"
    )

    path = write_pdf(sample_report, str(tmp_path / "markup.pdf"), verdict)
    assert open(path, "rb").read(5) == b"%PDF-"


def test_a_failed_censys_lookup_says_so_in_the_pdf(sample_report):
    """It used to render as a row of "None" -- the lookup failed and the PDF
    showed it as a host Censys had nothing on."""
    from hash_searcher.models import CensysHost

    sample_report.hosts = [CensysHost(ip="198.51.100.10", error="Censys 403: forbidden")]
    texts = _texts(build_story(sample_report, None))
    assert "Censys 403: forbidden" in texts
    assert "None" not in texts


def test_the_phase_4_sources_reach_the_pdf(sample_report):
    from hash_searcher.models import BazaarReport, KEVEntry, KEVReport, SourceResult
    from hash_searcher.render.pdf import build_story

    sample_report.bazaar = SourceResult(
        value=BazaarReport(found=True, family="Emotet"), queried=True)
    sample_report.kev = SourceResult(
        value=KEVReport(entries=[KEVEntry(cve="CVE-2021-41617", product="OpenSSH")]),
        queried=True)

    def _text(flowable) -> str:
        """Flatten a flowable: KEV and IP intel render as tables, whose cell
        Paragraphs are not reachable through the top-level .text."""
        rows = getattr(flowable, "_cellvalues", None)
        if rows:
            return " ".join(_text(cell) for row in rows for cell in row)
        return getattr(flowable, "text", "") or ""

    text = " ".join(_text(f) for f in build_story(sample_report))
    assert "MalwareBazaar" in text
    assert "Emotet" in text
    assert "CVE-2021-41617" in text


def test_write_pdf_survives_a_realistic_worst_case(tmp_path, sample_report):
    """build_story assertions cannot catch a layout failure -- only doc.build
    can. A reportlab table row does not split across pages, so an unbounded
    CVE cell raised LayoutError and took down an otherwise successful run at
    the very last step. Real Shodan answers carry 120-137 CVEs for one host.
    """
    from hash_searcher.api.api_data_puller import IOC_LIMIT
    from hash_searcher.models import (
        CertReport, GreyNoiseReport, KEVEntry, KEVReport, ShodanReport,
        SourceResult, ThreatFoxReport,
    )
    from hash_searcher.render.pdf import write_pdf
    from hash_searcher.scoring import score

    # Shodan at IOC_LIMIT hosts at 137 CVEs each, not one host at 150. Every
    # per-IP source is at the cap here, so the CVE column is laid out
    # IOC_LIMIT times rather than once.
    sample_report.shodan = {
        f"198.51.100.{n}": SourceResult(value=ShodanReport(
            ports=list(range(1, 40)),
            vulns=[f"CVE-2021-{c:05d}" for c in range(137)]), queried=True)
        for n in range(IOC_LIMIT)
    }
    # 200 KEV entries, and DELIBERATELY not the upper bound. known_exploited()
    # caps nothing, and the CVE list it intersects against the catalog is
    # bounded only by Shodan's vulns across every contacted IP -- IOC_LIMIT
    # hosts at the realistic 137 each is 6850. That is a bound, not a
    # reachable count: known_exploited de-duplicates those CVEs into a set
    # and intersects it with CISA's ~1,300-entry catalog, so the true
    # maximum is min(unique observed CVEs, catalog size). The bound
    # IS exercised, in test_the_pdf_backstop_never_fires_on_input_the_
    # puller_can_produce, which is where it belongs: the thing it proves is
    # that the KEV SIGNAL DETAIL stays bounded, and that costs nothing to
    # check without building a PDF.
    #
    # Building one used to be what made it expensive, for a reason
    # unrelated to this test: the "Known Exploited Vulnerabilities" table
    # emitted one ROW PER ENTRY, uncapped. That is not the crash this file
    # guards -- a many-row table splits across pages perfectly well -- but
    # layout time grew superlinearly with the row count: 200 entries 0.26s,
    # 1000 1.0s, 3000 3.6s, 6850 16.1s on the machine that first measured
    # it. KEV_ROW_LIMIT is why that bound is affordable here
    # now, and paying it is the point: 200 was a number chosen to keep the
    # suite fast, and this fixture is supposed to be the worst input the
    # puller can produce.
    sample_report.kev = SourceResult(value=KEVReport(entries=[
        KEVEntry(cve=f"CVE-2021-{n:05d}", vendor="Apache",
                product="HTTP Server", name="Some Vulnerability",
                date_added="2022-03-03") for n in range(IOC_LIMIT * 137)]),
        queried=True)
    sample_report.certs = SourceResult(value=CertReport(
        siblings=[f"host{n}.evil.example" for n in range(100)], count=5000),
        queried=True)
    # threatfox and greynoise complete the set: all three per-IP sources at
    # IOC_LIMIT, so the signals below are built from the worst per-IP input
    # the puller can hand the scorer rather than the two-of-three this
    # fixture used to carry. The 150 ThreatFox tags are a provider-supplied
    # list landing in a table cell, the same shape as the CVE column, and
    # capped for the same reason -- a row cannot split across pages.
    ips = [f"198.51.100.{n}" for n in range(IOC_LIMIT)]
    sample_report.threatfox_ips = {
        ip: SourceResult(value=ThreatFoxReport(
            found=True, malware="RedLine Stealer", confidence=90,
            tags=[f"tag-{n}" for n in range(150)]), queried=True)
        for ip in ips
    }
    sample_report.greynoise = {
        ip: SourceResult(value=GreyNoiseReport(
            seen=True, classification="benign", name="Shodan Scanner"),
            queried=True)
        for ip in ips
    }

    # THE POINT OF THE VERDICT ARGUMENT: build_story only lays out the
    # signals table when a verdict is passed, and that table is where three
    # signals -- threatfox, kev, internet_noise -- deposit joined provider
    # text into a row that cannot split across pages. Passing no verdict
    # left the one flowable most at risk out of the story entirely, which is
    # how an unbounded ThreatFox detail shipped green.
    #
    # score() rather than hand-built Signals: the caps that keep this
    # buildable live in scoring.py, so a hand-built Signal would test the
    # test's own arithmetic instead of the production path.
    verdict = score(sample_report)
    fired = {s.name: s for s in verdict.signals}
    assert {"threatfox", "kev", "internet_noise"} <= set(fired), (
        f"the three joined-detail signals must all fire here; got {set(fired)}"
    )

    out = tmp_path / "report.pdf"
    write_pdf(sample_report, str(out), verdict)
    assert out.stat().st_size > 0


def test_the_ip_table_carries_the_threatfox_column(sample_report):
    from hash_searcher.models import ShodanReport, SourceResult, ThreatFoxReport

    sample_report.shodan = {"198.51.100.10": SourceResult(
        value=ShodanReport(ports=[443]), queried=True)}
    sample_report.threatfox_ips = {"198.51.100.10": SourceResult(
        value=ThreatFoxReport(found=True, malware="Emotet", confidence=90,
                              tags=["botnet", "c2"]), queried=True)}
    texts = _texts(build_story(sample_report, None))
    assert "ThreatFox" in texts, "the IP table needs a ThreatFox header cell"
    assert any("Emotet" in t and "90%" in t for t in texts)
    assert any("botnet, c2" in t for t in texts)


def test_a_never_asked_per_ip_source_is_not_rendered_as_a_negative_finding(sample_report):
    """Carried from Task A2's review. "not observed" is a claim GreyNoise
    made; a result nobody asked for supports no claim at all, and stating
    the negative is worse than saying nothing on a report an analyst files.
    """
    from hash_searcher.models import ShodanReport, SourceResult

    sample_report.shodan = {"198.51.100.10": SourceResult(
        value=ShodanReport(ports=[443]), queried=True)}
    sample_report.greynoise = {"198.51.100.10": SourceResult()}
    sample_report.threatfox_ips = {"198.51.100.10": SourceResult()}

    texts = _texts(build_story(sample_report, None))
    assert any("443" in t for t in texts), "the row itself is still rendered"
    assert not any("not observed" in t for t in texts)
    assert not any("no record" in t for t in texts)


def test_the_pdf_ip_table_is_absent_when_no_per_ip_source_was_asked(sample_report):
    """pdf.py had the identical shape as tty.py's guard -- `if report.shodan
    or report.greynoise` tests the dicts, not the results, so a dict of
    never-asked results produced a heading and a table of empty rows."""
    from hash_searcher.models import SourceResult

    sample_report.shodan = {"198.51.100.10": SourceResult()}
    sample_report.greynoise = {"198.51.100.10": SourceResult()}
    sample_report.threatfox_ips = {"198.51.100.10": SourceResult()}

    texts = _texts(build_story(sample_report, None))
    assert "IP Intelligence" not in texts
    # The IP itself still appears in the AbuseIPDB and Censys tables, so the
    # column headers unique to this table are what prove it is absent.
    assert "GreyNoise" not in texts
    assert "ThreatFox" not in texts


def test_markup_in_a_threatfox_family_name_is_escaped_not_parsed(tmp_path, sample_report):
    """The new column is a provider value like every other one here, and
    `<script>`/`<title>` are payloads reportlab's paraparser actually
    rejects -- it silently discards a wholly unknown tag, so a payload it
    tolerates would prove nothing about _x()."""
    from hash_searcher.models import SourceResult, ThreatFoxReport

    sample_report.threatfox_ips = {"198.51.100.10": SourceResult(
        value=ThreatFoxReport(found=True, malware="<script>Emotet",
                              confidence=90, tags=["<title>", "c2"]),
        queried=True)}
    texts = _texts(build_story(sample_report, None))
    assert any("&lt;script&gt;Emotet" in t for t in texts)
    assert any("&lt;title&gt;" in t for t in texts)

    path = write_pdf(sample_report, str(tmp_path / "threatfox.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_any_signal_detail_is_bounded_before_it_reaches_the_table_cell(tmp_path, sample_report):
    """The backstop, not the per-signal cap.

    The crash is a property of the CELL, not of any one signal: a reportlab
    table row cannot split across pages, and five of the seven signal
    details in scoring.py are `", ".join(...)` over a provider-supplied
    list that nothing upstream caps -- kev (known_exploited caps nothing),
    yara and sandbox (analysis/vt.py caps only `names`), yara_local, and
    threatfox. Capping the one signal this task introduced would leave the
    other four one large provider answer away from the same crash.

    So the cell defends itself, and this is the READING half of that: a
    detail longer than DETAIL_CHAR_LIMIT is cut and says what it cut. The
    CRASH half is CELL_HEIGHT_LIMIT and
    test_one_provider_string_of_any_length_cannot_raise_a_layout_error --
    no character count can do that job, because 624pt of frame is 740
    characters of ("W" * 13 + " ") and 2669 of lowercase prose.
    """
    from hash_searcher.render.pdf import DETAIL_CHAR_LIMIT

    detail = "CVE-2021-99999, " * 400          # ~6400 characters
    verdict = Verdict(level="MALICIOUS", score=25, signals=[
        Signal(name="kev", points=25, detail=detail)])

    texts = _texts(build_story(sample_report, verdict))
    cell = next(t for t in texts if t.startswith("CVE-2021-99999"))
    assert len(cell) < len(detail)
    assert f"of {len(detail)} characters" in cell, (
        "a truncated detail must say it was truncated and how much there was"
    )
    # A hardcoded ceiling rather than one derived from DETAIL_CHAR_LIMIT:
    # widening the budget would otherwise recompute this test's own
    # expectation and pass.
    #
    # 1400 was justified here as leaving "real headroom" under a 1677
    # boundary, and that was true only of CVE content: this ceiling permits
    # a 1476-character cell, and ALL-CAPS prose crosses at 1570 and
    # ("W" * 13 + " ") at 740. It was a bound stated against the wrong
    # content class. It is not a crash bound at all now -- _fitted measures
    # the rendered height afterwards -- so what 1400 bounds is how much of
    # one rationale a filed report asks an analyst to read: about a third
    # of a page of the CVE list below, with the rest a JSON lookup.
    assert DETAIL_CHAR_LIMIT <= 1400

    # And it must actually build -- the assertion above is on the string,
    # and only doc.build() raises LayoutError.
    path = write_pdf(sample_report, str(tmp_path / "long_detail.pdf"), verdict)
    assert open(path, "rb").read(5) == b"%PDF-"


def test_a_normal_signal_detail_is_left_exactly_alone(sample_report):
    """The backstop must be invisible for every detail that renders today.
    internet_noise at IOC_LIMIT reaches ~808 characters -- the largest any
    real input produces now that the joined details are capped in
    scoring.py -- and it may not acquire a truncation marker."""
    from hash_searcher.render.pdf import DETAIL_CHAR_LIMIT

    detail = "GreyNoise calls these contacted IPs benign internet background noise: " \
             + ", ".join(f"198.51.100.{n}" for n in range(50))
    assert len(detail) < DETAIL_CHAR_LIMIT
    verdict = Verdict(level="CLEAN", score=-10, signals=[
        Signal(name="internet_noise", points=-10, detail=detail)])
    assert detail in _texts(build_story(sample_report, verdict))


def test_one_provider_string_of_any_length_cannot_raise_a_layout_error(
        tmp_path, sample_report):
    """A character count is not a bound on a table row's HEIGHT.

    Measured against a real write_pdf with the character backstop disabled,
    every shape crosses the frame at the same wrapped height while the
    character count that reaches it varies by 3.8x. Each payload is quoted,
    because a number whose input is only described cannot be re-derived:

        ("W" * 13 + " ") * n                          728
        ("W" * 10 + " ") * n                         1144
        "W" * n                                      1300
        ", ".join(f"CVE-2021-{i:05d}")               1662
        ", ".join("APT28_Sofacy_Downloader_Stage2")  1662
        ", ".join(f"198.51.100.{i % 256}")           2384
        "THE QUICK BROWN FOX " * n                   1820
        "the quick brown fox " * n                   2760

    So DETAIL_CHAR_LIMIT = 1200 is not a crash bound at all: against the
    first of those shapes it truncated to ~1276 characters and the
    TRUNCATED string still raised
    `LayoutError: ... (tallest row 1038) ... too large on page 2`.
    The cell is fitted by measured height instead, which is a bound on the
    thing that actually overflows.
    """
    from hash_searcher.render.pdf import CELL_HEIGHT_LIMIT, write_pdf

    detail = ("W" * 13 + " ") * 300          # 4200 characters, 5.8x the 728
    verdict = Verdict(level="MALICIOUS", score=10, signals=[
        Signal(name="yara", points=10, detail=detail)])

    # Hardcoded rather than derived from the frame: letter is 792pt tall,
    # SimpleDocTemplate's default margins take 72 top and 72 bottom, and the
    # Frame's own padding another 6 and 6, leaving 636pt for a flowable. A
    # ROW is its Paragraph plus reportlab's vertical cell padding, which is
    # 3 top and 3 bottom -- not the 6 of CELL_PADDING, which is horizontal
    # only -- so the Paragraph budget is 636 - 6 = 630. Bisected: a 630pt
    # row lays out and the next step, 654, does not. (This said 624 and
    # derived it by subtracting 6 and 6. 624 is the largest multiple of the
    # 12pt leading below 630, so it is what a bisection observes; the number
    # was right and the arithmetic was not.)
    assert CELL_HEIGHT_LIMIT <= 630

    path = write_pdf(sample_report, str(tmp_path / "wide.pdf"), verdict)
    assert open(path, "rb").read(5) == b"%PDF-"

    cell = next(t for t in _texts(build_story(sample_report, verdict))
                if t.startswith("WWW"))
    assert f"of {len(detail)} characters" in cell, (
        "a cell shortened to fit must say how much text there was")


def test_a_provider_string_in_the_ip_table_is_fitted_too(tmp_path, sample_report):
    """The signal detail is not the only provider string in a row that
    cannot split across pages. GreyNoise's `name` and ThreatFox's `malware`
    are unbounded strings straight from a provider, and nothing capped
    them: a 2100-character GreyNoise name raised
    `LayoutError: <Table 1 rows x 5 cols(tallest row 1962)>` from a real
    write_pdf. Every table cell carrying provider text is fitted, not just
    the one whose crash was reported."""
    from hash_searcher.models import GreyNoiseReport, ShodanReport, SourceResult

    sample_report.shodan = {"198.51.100.10": SourceResult(
        value=ShodanReport(ports=[80], vulns=[]), queried=True)}
    sample_report.greynoise = {"198.51.100.10": SourceResult(
        value=GreyNoiseReport(seen=True, classification="benign",
                              name=("W" * 13 + " ") * 150), queried=True)}

    path = write_pdf(sample_report, str(tmp_path / "wide_ip.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_the_kev_table_caps_its_rows_and_states_the_total(sample_report):
    """One row per entry, uncapped, against an upper bound of 6850 entries.

    A bound, not a reachable count: known_exploited (analysis/kev.py)
    de-duplicates the observed CVEs into a set and intersects it with CISA's
    catalog of ~1,300, so the true maximum is min(unique observed CVEs,
    catalog size). 6850 errs high, which is the right direction for a
    fixture and the wrong word for what it is.

    That never raises -- a many-row table splits across pages -- but layout
    time grows superlinearly with the row count: measured on this machine,
    200 entries 0.13s, 1000 0.65s, 3000 2.36s, 6850 6.82s for a 319 KiB
    PDF (a second machine measured the same shape at 11.4s). Capped like
    every other display cap here, with the untruncated total stated so the
    section never reads as the whole catalog.
    """
    from hash_searcher.models import KEVEntry, KEVReport, SourceResult
    from hash_searcher.render.pdf import KEV_ROW_LIMIT

    sample_report.kev = SourceResult(value=KEVReport(entries=[
        KEVEntry(cve=f"CVE-2021-{n:05d}", vendor="Apache", product="HTTP Server",
                 name="Some Vulnerability", date_added="2022-03-03")
        for n in range(60)]), queried=True)

    story = build_story(sample_report)
    kev_table = next(f for f in story
                     if isinstance(f, Table) and f._cellvalues[0][0] == "CVE")
    assert len(kev_table._cellvalues) == KEV_ROW_LIMIT + 1, "header plus the cap"

    texts = _texts(story)
    assert any("60 known exploited vulnerabilities (showing " in t for t in texts), (
        "the untruncated total must be stated beside the shortened table")
    assert any("CVE-2021-00000" in t for t in texts)
    assert not any("CVE-2021-00059" in t for t in texts)

    # A hardcoded ceiling, not one derived from KEV_ROW_LIMIT. 100 rows is
    # 0.07s and about two pages of table; the uncapped 6850 is 6.8-11.4s and
    # 130 pages, which no reader of a filed report can use. The full list
    # stays in the JSON report either way.
    assert KEV_ROW_LIMIT <= 100


#: The height a Table gets on a fresh page, in points, and the number
#: reportlab compares its tallest row against before raising LayoutError.
#: Hardcoded rather than read back off a SimpleDocTemplate: letter is 792pt,
#: the default margins write_pdf accepts take 72 top and 72 bottom, and the
#: Frame's own padding another 6 and 6. A row taller than this cannot be
#: laid out anywhere, because a table row does not split across pages.
FRAME_HEIGHT = 636

#: Frame width, by the same arithmetic across the 612pt page: 612 - 72 - 72
#: - 6 - 6. Only used to make the tables below wrap at a realistic width.
FRAME_WIDTH = 456


def _oversized_report(sample_report):
    """A report in which every provider value a table can render is too big.

    Deliberately built by field rather than by table: the test below
    ENUMERATES the tables build_story produces, so a table added later is
    covered the moment it renders any of these fields.

    Every string here is 1008 characters of the widest shape measured -- a
    13-W token crosses the 630pt row budget at 728 characters in the widest
    column any of these tables has (250pt), so this is 1.4x over there and
    far more in the 55pt one. Kept well below the 4200 the crash was
    reported at because the height fit binary-searches and its cost tracks
    the length it starts from; the caller checks that premise against the
    live widths rather than trusting this comment.
    """
    from hash_searcher.models import (
        CensysHost, GreyNoiseReport, IPReport, KEVEntry, KEVReport,
        ShodanReport, SourceResult, ThreatFoxReport, WhoisRecord,
    )

    big = ("W" * 13 + " ") * 72
    ip = "198.51.100.10"

    sample_report.ips = {ip: IPReport(ip=big, confidence=big, reports=big)}
    sample_report.hosts = [
        CensysHost(ip=big, org=big, asn=big, country=big,
                   ports=list(range(1, 121))),
        CensysHost(ip=big, error=big),
    ]
    sample_report.whois = [WhoisRecord(domain=big, created=big, expires=big,
                                       registrar=big)]
    sample_report.shodan = {ip: SourceResult(value=ShodanReport(
        ports=list(range(1, 121)),
        vulns=[f"CVE-2021-{n:05d}" for n in range(300)]), queried=True)}
    sample_report.greynoise = {ip: SourceResult(value=GreyNoiseReport(
        seen=True, classification=big, name=big), queried=True)}
    sample_report.threatfox_ips = {ip: SourceResult(value=ThreatFoxReport(
        found=True, malware=big, confidence=95,
        tags=[big[:60] for _ in range(50)]), queried=True)}
    sample_report.kev = SourceResult(value=KEVReport(entries=[
        KEVEntry(cve=big, vendor=big, product=big, date_added=big)]),
        queried=True)

    verdict = Verdict(level="MALICIOUS", score=99, signals=[
        Signal(name=big, points=50, detail=big)])
    return sample_report, verdict


def test_every_table_the_report_builds_fits_an_oversized_provider_value(
        tmp_path, sample_report):
    """The bound is per TABLE, and three rounds of this fix covered a subset.

    A4 capped ThreatFox's tags and missed the signal detail; A4b capped how
    many items a detail names and missed how long one is; A4c fitted the
    signal, IP and KEV tables and missed Censys and WHOIS -- each round
    generalised the rule correctly and then applied it to some of the sites
    the rule covers. So this asserts over every Table build_story emits
    rather than over a list of them, and a table added later is covered
    without anyone remembering to come back here.

    Reproduced before the fix, from a real write_pdf:

        Censys ports, 280 services  LayoutError <1 rows x 5 cols(tallest row 930)>
        Censys org 4200 chars       LayoutError <1 rows x 5 cols(tallest row 4266)>
        WHOIS registrar 4200 chars  LayoutError <1 rows x 4 cols(tallest row 3606)>

    280 Censys services needs no hostile input at all: `ports` at
    analysis/censys.py is a plain provider list with no cap, and 279 build
    where 280 raise.
    """
    from hash_searcher.render.pdf import (
        ABUSE_WIDTHS, CENSYS_WIDTHS, IP_WIDTHS, KEV_WIDTHS, SIGNAL_WIDTHS,
        WHOIS_WIDTHS, _cell_height,
    )

    report, verdict = _oversized_report(sample_report)

    # The fixture's own premise, checked rather than assumed: the payload
    # must still overflow the WIDEST column any of these tables has, or a
    # later width change quietly turns this into a test of nothing.
    widest = max(w for widths in (SIGNAL_WIDTHS, IP_WIDTHS, KEV_WIDTHS,
                                  ABUSE_WIDTHS, CENSYS_WIDTHS, WHOIS_WIDTHS)
                 for w in widths)
    assert _cell_height(verdict.signals[0].detail, widest) > FRAME_HEIGHT, (
        f"the oversized payload fits in a {widest}pt column -- it is not "
        f"oversized any more")

    story = build_story(report, verdict)
    tables = [f for f in story if isinstance(f, Table)]

    # Five today: verdict signals, AbuseIPDB, Censys, WHOIS, IP intel, KEV.
    assert len(tables) >= 5, "the fixture must actually reach every table"

    def _header(table):
        return " | ".join(str(c) for c in table._cellvalues[0])

    # Snapshot the body cells BEFORE anything wraps: Table.wrap rewrites
    # _cellvalues into its own _ExpandedCellTuple wrappers, and the
    # structural half of this assertion is about what build_story put there.
    bodies = {id(t): [list(row) for row in t._cellvalues[1:]] for t in tables}

    for table in tables:
        table.wrap(FRAME_WIDTH, FRAME_HEIGHT)
        # _rowHeights is the exact quantity reportlab names in the
        # LayoutError it raises ("tallest row 930"), which is why the
        # assertion is made against it rather than against the total.
        tallest = max(table._rowHeights)
        assert tallest <= FRAME_HEIGHT, (
            f"a row of the [{_header(table)}] table is {tallest}pt tall and "
            f"cannot split across pages -- it will raise LayoutError")

    # And the structural half: a cell that was never measured is a cell the
    # height assertion above only happens to pass for, on this fixture.
    for table in tables:
        for row in bodies[id(table)]:
            for cell in row:
                assert isinstance(cell, Paragraph), (
                    f"a body cell of the [{_header(table)}] table is a bare "
                    f"{type(cell).__name__} -- it was not measured against "
                    f"the column it lands in")

    # And the real thing: only doc.build() raises the failure this guards.
    path = write_pdf(report, str(tmp_path / "oversized.pdf"), verdict)
    assert open(path, "rb").read(5) == b"%PDF-"


def test_no_table_is_wider_than_the_page():
    """The other half of the widths block, and it drifted once already: the
    IP table's five columns summed to 460pt inside a 456pt frame.

    Enumerated off the module rather than listed, for the same reason as the
    test above -- a sixth table's widths are covered the moment they are
    named here. A column wider than the frame does not raise, which is why
    nothing caught it: reportlab draws the overflow off the edge of the
    paper, and the fit then measures a cell against a width the reader never
    gets.
    """
    from hash_searcher.render import pdf as pdf_module

    blocks = {name: value for name, value in vars(pdf_module).items()
              if name.endswith("_WIDTHS")}
    assert len(blocks) >= 6, (
        f"only {sorted(blocks)} -- a table's widths are defined somewhere "
        f"other than the widths block")
    for name, widths in blocks.items():
        assert sum(widths) <= FRAME_WIDTH, (
            f"{name} sums to {sum(widths)}pt in a {FRAME_WIDTH}pt frame")


def test_the_censys_table_fits_a_host_with_many_services(tmp_path, sample_report):
    """Censys `ports` is uncapped and needs no hostile provider to overflow.

    analysis/censys.py builds it from every service on the host. Bisected
    against a real write_pdf: 279 services lay out and 280 raise
    `LayoutError: <Table 1 rows x 5 cols(tallest row 930)>`. Shodan's ports
    go through the fitter in the IP table; Censys's identical data did not.
    """
    from hash_searcher.models import CensysHost

    sample_report.hosts = [CensysHost(ip="198.51.100.10", org="Example AS",
                                      asn=64496, country="NL",
                                      ports=list(range(1, 281)))]
    path = write_pdf(sample_report, str(tmp_path / "censys_ports.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_the_censys_table_fits_an_unbounded_org_name(tmp_path, sample_report):
    """`org` is the AS name straight off the provider, with no bound at all.

    Both branches of the Censys row are exercised: the error branch renders
    `h.error`, which is provider text too and was equally unfitted.
    """
    from hash_searcher.models import CensysHost

    big = ("W" * 13 + " ") * 300
    sample_report.hosts = [
        CensysHost(ip="198.51.100.10", org=big, asn=64496, country="NL",
                   ports=[80]),
        CensysHost(ip="198.51.100.11", error=big),
    ]
    path = write_pdf(sample_report, str(tmp_path / "censys_org.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_the_whois_table_fits_an_unbounded_registrar(tmp_path, sample_report):
    """WHOIS is the fifth table, and `registrar` and `domain` are both raw
    provider strings: 4200 characters of either raised
    `LayoutError: <Table 1 rows x 4 cols(tallest row 3606)>`."""
    from hash_searcher.models import WhoisRecord

    big = ("W" * 13 + " ") * 300
    sample_report.whois = [WhoisRecord(domain=big, created="2020-01-01",
                                       expires="2027-01-01", registrar=big)]
    path = write_pdf(sample_report, str(tmp_path / "whois.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_a_provider_value_carrying_newlines_cannot_overflow_a_row(
        tmp_path, sample_report):
    """A bare-string table cell is NOT safe just because it does not wrap.

    reportlab splits a string cell on '\\n' and gives it one line per piece,
    so 200 newlines is a 2406pt row and a LayoutError -- measured. The
    AbuseIPDB table was left as bare strings on the reasoning that an
    unwrapped cell cannot overflow by height; it can, and
    `analysis/ipdb.py` takes `ip` straight from the provider's `ipAddress`
    with no validation, so this is reachable rather than theoretical.
    """
    from hash_searcher.models import IPReport

    newlines = "\n".join(f"line {n}" for n in range(200))
    sample_report.ips = {"198.51.100.10": IPReport(
        ip=newlines, confidence=newlines, reports=newlines)}
    path = write_pdf(sample_report, str(tmp_path / "newlines.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_fitting_a_huge_string_never_measures_more_than_the_ceiling(
        monkeypatch, sample_report):
    """The height fit is a binary search, but its FIRST measurement was the
    whole string.

    Every call site except the signal detail passes no char_limit, so a
    200,000-character GreyNoise name wrapped 200,000 characters before the
    search could narrow anything -- 1.8s here, and 42s at 2M. The ceiling
    makes the work independent of how much text the provider sent.

    Asserted by recording what actually gets measured rather than by the
    clock, which would be flaky. 20000 is a hardcoded ceiling, not one read
    back off the constant: the widest column a 456pt frame allows is 444pt
    of text, and the narrowest glyph in this font reaches the 630pt budget
    at 12064 characters, so nothing that would otherwise have fitted is
    lost.
    """
    from hash_searcher.render import pdf as pdf_module

    assert pdf_module.FIT_CHAR_CEILING <= 20000

    measured = []
    real = pdf_module._cell_height
    monkeypatch.setattr(pdf_module, "_cell_height",
                        lambda text, width: measured.append(len(text)) or real(text, width))

    cell = pdf_module._fitted("W" * 200_000, 250)
    assert measured, "the fit must measure something"
    assert max(measured) <= pdf_module.FIT_CHAR_CEILING + 200, (
        f"the fit wrapped {max(measured)} characters; the ceiling is "
        f"{pdf_module.FIT_CHAR_CEILING}")
    assert "of 200000 characters" in cell.text, (
        "a cell cut by the ceiling must still state the untruncated total")
