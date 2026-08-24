import pytest

from hash_searcher.cli import build_parser, output_format


def test_positional_indicator_is_required():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_output_flag_is_optional():
    args = build_parser().parse_args(["abc123"])
    assert args.indicator == "abc123"
    assert args.output is None


def test_short_and_long_output_flags_agree():
    parser = build_parser()
    assert parser.parse_args(["abc", "-o", "r.json"]).output == "r.json"
    assert parser.parse_args(["abc", "--output", "r.json"]).output == "r.json"


@pytest.mark.parametrize("name,expected", [
    ("report.json", "json"),
    ("report.pdf", "pdf"),
    ("REPORT.JSON", "json"),
    ("report.txt", None),
])
def test_output_format_is_chosen_by_extension(name, expected):
    assert output_format(name) == expected


def test_zip_password_flag_is_accepted():
    assert build_parser().parse_args(["a.zip", "--zip-password", "s3cret"]).zip_password == "s3cret"
