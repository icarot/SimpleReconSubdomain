import httpx
from sources.base import BaseSource
from core.config import get_key


class URLScan(BaseSource):
    NAME = 'urlscan'
    DESCRIPTION = 'URLScan.io scan history'
    API_TOKEN_IS_REQUIREMENT = False

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
                resp = await self._get(client, url)
                if resp.status_code != 200:
                    return subdomains
                for result in resp.json().get('results', []):
                    page = result.get('page', {})
                    for key in ('domain', 'ptr'):
                        val = page.get(key, '')
                        if val:
                            subdomains.add(val)
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
