# Vendored data

## `mitre-attack-enterprise.json`

A reduced copy of the MITRE ATT&CK Enterprise STIX bundle, used by
`analysis/attack.py` to turn technique IDs into names, tactics, and links.

Vendored rather than fetched: the spec puts a "no key, no internet"
guarantee on the offline path, and a network call at resolve time would
break it.

| | |
|---|---|
| Upstream | <https://github.com/mitre/cti> |
| Release tag | `ATT&CK-v15.1` (URL-encoded `ATT%26CK-v15.1`) |
| Retrieved | 2026-08-25 |
| Objects kept | 649 non-revoked `attack-pattern` objects |
| Size | 26 MB upstream, 897 KB reduced |
| SHA-256 (upstream) | `39b1f158c2e1c604801da2f75b2be9e6a448a7250d69db628168a0f7be056349` |
| SHA-256 (reduced) | `e1c8bcb3edb49a4e4a5c11bcabedf7f50840099f9792942d66ca176783f54f0d` |

### Refreshing it

```bash
curl -fsSL -o /tmp/enterprise-attack.json \
  "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v15.1/enterprise-attack/enterprise-attack.json"
./venv/bin/python scripts/reduce_attack_bundle.py \
  /tmp/enterprise-attack.json src/ioc_inquest/data/mitre-attack-enterprise.json
sha256sum /tmp/enterprise-attack.json src/ioc_inquest/data/mitre-attack-enterprise.json
```

Bump the tag in the URL to move to a newer ATT&CK release, then update the
table above. The `&` in the tag must stay percent-encoded; the bare form
404s.

`scripts/reduce_attack_bundle.py` keeps only `id`, `name`,
`external_references`, `kill_chain_phases`, and `type` — the five fields
`analysis/attack.py` reads. Everything else upstream ships is prose this
tool never displays.
