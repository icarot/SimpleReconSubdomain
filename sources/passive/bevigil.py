"""
BeVigil OSINT — mobile app subdomain extraction.

BeVigil indexes hundreds of thousands of mobile app APKs and extracts hardcoded
API endpoints, CDN origins, and domain references. Subdomains found here are
often absent from CT logs and code-search sources because they only appear
inside compiled app binaries.

API key required (free tier available): https://bevigil.com/osint-api
"""
from core.config import get_key
from sources.base import BaseSource


class Bevigil(BaseSource):
    NAME = 'bevigil'
    DESCRIPTION = 'BeVigil OSINT — mobile app/APK subdomain extraction'
    API_TOKEN_IS_REQUIREMENT = True

    _BASE_URL = 'https://osint.bevigil.com/api/{domain}/subdomains/'

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('bevigil_key')
        if not api_key:
            return set()

        subdomains: set[str] = set()
        url = self._BASE_URL.format(domain=domain)

        try:
            async with self._make_client(headers={'X-Access-Token': api_key}) as client:
                resp = await self._get(client, url)
                if resp.status_code == 401:
                    self._vlog(1, 'invalid API key')
                    return set()
                if resp.status_code == 404:
                    return set()
                if resp.status_code == 429:
                    self._vlog(1, 'rate limited')
                    return set()
                if resp.status_code != 200:
                    return set()
                for sub in resp.json().get('subdomains', []):
                    if sub:
                        subdomains.add(sub.strip().lower())
        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
