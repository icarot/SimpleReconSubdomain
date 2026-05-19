import httpx
from sources.base import BaseSource
from core.config import get_key


class URLScan(BaseSource):
    NAME = 'urlscan'

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200'
        subdomains: set[str] = set()
        headers = {}
        api_key = get_key('urlscan')
        if api_key:
            headers['API-Key'] = api_key

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, headers=headers
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains
                for result in resp.json().get('results', []):
                    page = result.get('page', {})
                    for key in ('domain', 'ptr'):
                        val = page.get(key, '')
                        if val:
                            subdomains.add(val)
        except Exception:
            pass
        return self._filter(subdomains, domain)
