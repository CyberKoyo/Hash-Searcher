"""AlienVault OTX. One endpoint per indicator type.

`indicator_type` is a keyword with a default, per the registry contract --
every provider stays callable as fetch(client, indicator).
"""

from urllib.parse import quote

import httpx

from . import config
from .base_call import api_get

#: What OTX calls each of this tool's indicator kinds, for the message on a
#: 404. Phase 5B made this provider reachable for ip/domain/url indicators,
#: at which point a fixed "Hash not found" answered a question nobody asked.
_SUBJECTS = {"file": "Hash", "IPv4": "IP", "IPv6": "IP",
             "domain": "Domain", "url": "URL"}


async def get_otx(client: httpx.AsyncClient, indicator, indicator_type="file"):
    # quote(safe=""), because the indicator is one path SEGMENT and a URL
    # indicator is full of characters that are not. Interpolated raw,
    # "https://evil.example/path?q=1" made httpx read the "?" as the start
    # of the query string: the request went to
    # /api/v1/indicators/url/https://evil.example/path with a query of
    # "q=1/general" -- the "/general" suffix swallowed, the endpoint never
    # reached, and the 404 that came back read as "OTX has never seen it".
    subject = _SUBJECTS.get(indicator_type, "Indicator")
    return await api_get(
        client,
        "https://otx.alienvault.com/api/v1/indicators/"
        f"{indicator_type}/{quote(str(indicator), safe='')}/general",
        {"accept": "application/json", "X-OTX-API-KEY": config.key("OTX_KEY") or ""},
        source="GetOTX",
        not_found=f"{subject} not found in GetOTX",
    )
