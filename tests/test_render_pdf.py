from hash_searcher.render.pdf import write_pdf


def test_write_pdf_creates_a_pdf(tmp_path, sample_report):
    path = write_pdf(sample_report, str(tmp_path / "out.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"


def test_write_pdf_handles_a_report_with_no_ips(tmp_path, sample_report):
    sample_report.ips, sample_report.hosts, sample_report.whois = {}, [], []
    path = write_pdf(sample_report, str(tmp_path / "empty.pdf"))
    assert open(path, "rb").read(5) == b"%PDF-"
