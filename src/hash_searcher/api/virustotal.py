"""VirusTotal fetcher.

Note the import direction: this module reaches into `analysis/`, which is the
reverse of the usual api -> analysis -> render flow. It is deliberate --
`contacted_ips` and `analysis.vt.relationship_ids` had diverged, and one of
them guarded a missing "id" key while the other raised KeyError (ruling R31).
Delegating rather than keeping a second copy is what closed that. The chain is
api.virustotal -> analysis.vt -> api.base_call, which is not a cycle; do not
"fix" it by importing back this way.
"""

import httpx

from ..analysis.vt import relationship_ids
from . import config
from .base_call import api_get

VT_FILES_URL = 'https://www.virustotal.com/api/v3/files'


async def get_vt(client: httpx.AsyncClient, hash) -> dict:
    """Fetch a file report and its contacted IPs in a single request.

    The ?relationships= response is a superset of the plain file response --
    data.attributes is identical either way -- so one call feeds both the sigma
    rules and the IP list. VirusTotal's free tier allows 4 requests/min and
    500/day, so the second call was pure waste.

    Returns the payload alone. The IP list is pulled out by contacted_ips()
    so this matches every other provider's (client, indicator) -> payload shape.
    """
    return await api_get(
        client,
        f'{VT_FILES_URL}/{hash}',
        {"accept": "application/json", "x-apikey": config.key("TOTAL_KEY") or ""},
        params={'relationships': 'contacted_ips,contacted_domains'},
        source='GetTotal',
        not_found='Hash not found in GetTotal',
    )


def contacted_ips(payload: dict) -> list[str]:
    """IPs the sample contacted, per VT. [] on any error payload.

    Delegates to analysis.vt._relationship_ids rather than repeating the
    walk. The two used to disagree: this one did an unguarded entry['id'],
    so a VT entry missing `id` raised KeyError out of data_puller and killed
    the run, while extract_vt skipped it on the same payload. Skipping is the
    better behavior and it lives in the layer that owns pure extraction.
    """
    return relationship_ids(payload, 'contacted_ips')


def contacted_domains(payload: dict) -> list[str]:
    """Domains the sample contacted, per VT. [] on any error payload.

    Same delegation as contacted_ips above, for the same reason. These are
    what the domain-typed providers (RDAP, crt.sh) are run over.
    """
    return relationship_ids(payload, 'contacted_domains')
