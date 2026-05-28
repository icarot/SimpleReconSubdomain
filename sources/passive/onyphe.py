import httpx
from sources.base import BaseSource
from core.config import get_key


class Onyphe(BaseSource):
    NAME = 'onyphe'
    DESCRIPTION = 'Onyphe.io - threat intelligence and internet asset discovery'
    API_TOKEN_IS_REQUIREMENT = True

    _BASE_URL = 'https://www.onyphe.io/api/v2/search/'
    _PAGE_SIZE = 100

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('onyphe_key')
        if not api_key:
            return set()

        headers = {'Authorization': f'bearer {api_key}'}
        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                page = 1
                while True:
                    params = {
                        'q': f'domain:{domain}',
                        'page': page,
                        'size': self._PAGE_SIZE,
                    }
                    resp = await self._get(client, self._BASE_URL, params=params, headers=headers)

                    if resp.status_code == 401:
                        self._vlog(1, 'invalid or expired API key')
                        break
                    if resp.status_code == 429:
                        self._vlog(1, 'rate limit reached')
                        break
                    if resp.status_code != 200:
                        self._vlog(2, f'unexpected status {resp.status_code}')
                        break

                    data = resp.json()
                    results = data.get('results', [])
                    if not results:
                        break

                    for entry in results:
                        for field in ('hostname', 'domain', 'forward'):
                            val = entry.get(field, '')
                            if val:
                                subdomains.add(val.strip().lower())

                    if page >= data.get('max_page', 1):
                        break
                    page += 1

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
