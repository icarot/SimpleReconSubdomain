"""
CIRCL Passive DNS — free academic passive DNS (Luxembourg).

Queries the CIRCL (Computer Incident Response Center Luxembourg) passive DNS
database. Returns A/AAAA/CNAME records seen for the domain and its subdomains.

No API key required for the community tier, but access is rate-limited.
Optional Basic-auth credentials for the authenticated tier:
  circl_user / circl_pass  (config/api_keys.json)

Reference: https://www.circl.lu/services/passive-dns/
"""
import json

from core.config import get_key
from sources.base import BaseSource


class Circl(BaseSource):
    NAME = 'circl'
    DESCRIPTION = 'CIRCL Passive DNS — free academic passive DNS (Luxembourg)'
    API_TOKEN_IS_REQUIREMENT = False

    _BASE_URL = 'https://www.circl.lu/pdns/query/{domain}'

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()

        user = get_key('circl_user')
        passw = get_key('circl_pass')
        auth = (user, passw) if user and passw else None

        url = self._BASE_URL.format(domain=domain)

        try:
            async with self._make_client() as client:
                kwargs: dict = {}
                if auth:
                    kwargs['auth'] = auth
                resp = await self._get(client, url, **kwargs)

                if resp.status_code in (401, 403):
                    self._vlog(1, 'authentication required — set circl_user/circl_pass or access is restricted')
                    return set()
                if resp.status_code == 429:
                    self._vlog(1, 'rate limited')
                    return set()
                if resp.status_code != 200:
                    return set()

                # Response is NDJSON (one JSON object per line)
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    rrname = (entry.get('rrname') or '').rstrip('.').lower()
                    if rrname:
                        subdomains.add(rrname)

                    rdata = entry.get('rdata') or ''
                    if isinstance(rdata, str):
                        rdata = rdata.rstrip('.').lower()
                        # Only add rdata if it looks like a hostname (CNAME target), not an IP
                        if rdata and '.' in rdata and not rdata.replace('.', '').isdigit():
                            subdomains.add(rdata)

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
