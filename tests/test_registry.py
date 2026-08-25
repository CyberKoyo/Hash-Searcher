from hash_searcher.api.registry import Provider, available, missing_keys


def _providers():
    return [
        Provider(name="vt", key_env="TOTAL_KEY", key_value="set",
                 indicator_types=("hash",), fetch=None),
        Provider(name="censys", key_env="CENSYS_KEY", key_value=None,
                 indicator_types=("ip",), fetch=None, serial_delay=2.0),
        Provider(name="crtsh", key_env=None, key_value=None,
                 indicator_types=("domain",), fetch=None),
    ]


def test_providers_with_a_key_are_available():
    assert [p.name for p in available(_providers())] == ["vt", "crtsh"]


def test_keyless_providers_are_always_available():
    assert any(p.name == "crtsh" for p in available(_providers()))


def test_missing_keys_names_the_env_vars():
    assert missing_keys(_providers()) == ["CENSYS_KEY"]


def test_serial_delay_defaults_to_zero():
    assert Provider(name="x", key_env=None, key_value=None,
                    indicator_types=("hash",), fetch=None).serial_delay == 0.0


def test_real_registry_covers_the_four_current_sources():
    from hash_searcher.api.registry import PROVIDERS
    assert {p.name for p in PROVIDERS} == {"virustotal", "otx", "abuseipdb", "censys"}
