import httpx
from sources.base import BaseSource
from core.config import get_key


class LeakIX(BaseSource):
    """
    Queries LeakIX for subdomains of the target domain.

    LeakIX continuously scans the internet and indexes exposed services,
    including Azure-hosted assets (App Service, Blob Storage, CDN, etc.).
    The endpoint returns plain subdomain strings already filtered to the
    target domain, so most results will be Azure-related infrastructure.

    API key (leakix_token) is optional: unauthenticated requests are
    rate-limited; a token provides higher throughput.
    """

    NAME = 'leakix'
    DESCRIPTION = 'LeakIX cloud/Azure asset index'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        token = get_key('leakix_token')
        headers: dict = {'accept': 'application/json'}
        if token:
            headers['api-key'] = token

        url = f'https://leakix.net/api/subdomains/{domain}'
        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, headers=headers
            ) as client:
                resp = await self._get(client, url)
                if resp.status_code != 200:
                    return subdomains

                data = resp.json()
                # Response is a list of subdomain strings or dicts with a
                # 'subdomain' / 'host' key depending on the API version.
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, str):
                            subdomains.add(entry.strip().lower())
                        elif isinstance(entry, dict):
                            for key in ('subdomain', 'host', 'hostname'):
                                val = entry.get(key, '')
                                if val:
                                    subdomains.add(val.strip().lower())
                                    break

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
