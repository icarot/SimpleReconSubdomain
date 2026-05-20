import httpx
from sources.base import BaseSource
from core.config import get_key


class Censys(BaseSource):
    NAME = 'censys'
    REQUIRES_API_KEY = True

    _SEARCH_URL = 'https://search.censys.io/api/v2/certificates/search'

    async def fetch(self, domain: str) -> set[str]:
        token = get_key('censys_token')
        if not token:
            return set()

        subdomains: set[str] = set()
        headers = {'Authorization': f'Bearer {token}'}
        self.timeout = 30
        params: dict = {
            'q': f'parsed.names: %.{domain}',
            'fields': 'parsed.names',
            'per_page': 100,
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, headers=headers
            ) as client:
                while True:
                    resp = await client.get(
                        self._SEARCH_URL,
                        params=params,
                    )
                    if resp.status_code != 200:
                        break
                    data = resp.json()
                    for hit in data.get('result', {}).get('hits', []):
                        for name in hit.get('parsed', {}).get('names', []):
                            subdomains.add(name)
                    cursor = (
                        data.get('result', {})
                        .get('links', {})
                        .get('next', '')
                    )
                    if not cursor:
                        break
                    params['cursor'] = cursor
        except Exception:
            pass

        return self._filter(subdomains, domain)
