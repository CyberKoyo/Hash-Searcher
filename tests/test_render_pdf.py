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

    sample_report.shodan = {
        "198.51.100.10": SourceResult(value=ShodanReport(
            ports=list(range(1, 40)),
            vulns=[f"CVE-2021-{n:05d}" for n in range(150)]), queried=True),
    }
    # 200, not 60: known_exploited() caps nothing, and the CVE list it
    # intersects against the catalog is bounded only by Shodan's vulns
    # across every contacted IP -- 150 for one host here, and IOC_LIMIT
    # hosts are possible. 60 was an arbitrary number under the threshold.
    sample_report.kev = SourceResult(value=KEVReport(entries=[
        KEVEntry(cve=f"CVE-2021-{n:05d}", vendor="Apache",
                product="HTTP Server", name="Some Vulnerability",
                date_added="2022-03-03") for n in range(200)]), queried=True)
    sample_report.certs = SourceResult(value=CertReport(
        siblings=[f"host{n}.evil.example" for n in range(100)], count=5000),
        queried=True)
    # ThreatFox tags are a provider-supplied list landing in a table cell,
    # the same shape as the CVE column, so they are capped for the same
    # reason: a row cannot split across pages.
    sample_report.threatfox_ips = {
        "198.51.100.10": SourceResult(value=ThreatFoxReport(
            found=True, malware="Emotet",
            confidence=90, tags=[f"tag-{n}" for n in range(150)]), queried=True),
    }

    # Every per-IP source at IOC_LIMIT, so the signals below are built from
    # the worst input the puller can actually hand the scorer.
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

    So the cell defends itself. The measured threshold for this column is
    2445 characters; the budget is well under it, and the truncation says
    what it did rather than dropping the tail silently.
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
    # widening the budget past the measured 2445-character crash threshold
    # would otherwise recompute this test's own expectation and pass.
    assert DETAIL_CHAR_LIMIT <= 2000

    # And it must actually build -- the assertion above is on the string,
    # and only doc.build() raises LayoutError.
    path = write_pdf(sample_report, str(tmp_path / "long_detail.pdf"), verdict)
    assert open(path, "rb").read(5) == b"%PDF-"


def test_a_normal_signal_detail_is_left_exactly_alone(sample_report):
    """The backstop must be invisible for every detail that renders today.
    internet_noise at IOC_LIMIT reaches ~808 characters and kev at 60 CVEs
    ~1019; neither may acquire a truncation marker."""
    from hash_searcher.render.pdf import DETAIL_CHAR_LIMIT

    detail = "GreyNoise calls these contacted IPs benign internet background noise: " \
             + ", ".join(f"198.51.100.{n}" for n in range(50))
    assert len(detail) < DETAIL_CHAR_LIMIT
    verdict = Verdict(level="CLEAN", score=-10, signals=[
        Signal(name="internet_noise", points=-10, detail=detail)])
    assert detail in _texts(build_story(sample_report, verdict))
