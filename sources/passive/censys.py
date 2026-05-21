import httpx
from sources.base import BaseSource
from core.config import get_key


class Censys(BaseSource):
    NAME = 'censys'
    DESCRIPTION = 'Censys certificate search'
    API_TOKEN_IS_REQUIREMENT = True

    _SEARCH_URL = 'https://search.censys.io/api/v2/certificates/search'

    async def fetch(self, domain: str) -> set[str]:
        api_id = get_key('censys_id')
        api_secret = get_key('censys_secret')
        if not api_id or not api_secret:
            return set()

        subdomains: set[str] = set()
        self.timeout = 30
        params: dict = {
            'q': f'parsed.names: %.{domain}',
            'fields': 'parsed.names',
            'per_page': 100,
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, auth=(api_id, api_secret)
            ) as client:
                while True:
                    resp = await self._get(
                        client,
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
        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
