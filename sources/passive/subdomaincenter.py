"""
SubdomainCenter source (Netcraft mirror).

Free subdomain enumeration endpoint aggregating multiple passive sources.
No API key required.
Reference: https://api.subdomain.center/
"""
import httpx

from sources.base import BaseSource


class Subdomaincenter(BaseSource):
    NAME = 'subdomaincenter'
    DESCRIPTION = 'SubdomainCenter - Netcraft-backed free subdomain index'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await self._get(
                    client,
                    'https://api.subdomain.center/',
                    params={'domain': domain},
                )
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, str) and entry.strip():
                            subdomains.add(entry.strip().lower())
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
