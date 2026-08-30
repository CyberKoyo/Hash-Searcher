"""crt.sh certificate transparency. Keyless, domain indicators.

Certificate transparency reveals sibling domains issued on the same
certificate -- often the rest of an actor's infrastructure, discovered
from a single domain.

crt.sh throttles anonymous bulk queries, which is why the registry entry
carries serial_delay=2.0 and why base_call sends a User-Agent naming this
tool (Constraint 7). Under load it answers 200 with an HTML error page
rather than JSON; api_get normalizes that to an error dict.
"""

import httpx

from .base_call import api_get

CRTSH_URL = "https://crt.sh/"


async def get_crtsh(client: httpx.AsyncClient, domain, **kwargs):
    return await api_get(
        client,
        CRTSH_URL,
        {"accept": "application/json"},
        # %.<domain> is crt.sh's own wildcard: subdomains as well as the
        # apex. The literal % must reach the server, so it goes through
        # params rather than being baked into the URL.
        params={"q": f"%.{domain}", "output": "json"},
        source="crt.sh",
        not_found=f"No certificates found for {domain}",
        **kwargs,
    )
