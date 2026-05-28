"""
Hunter.how — asset database with strong EU/APAC coverage.

Queries the Hunter.how search engine for assets belonging to the target domain.
Useful as a complement to Shodan/FOFA, particularly for European and APAC infra.

API key required: https://hunter.how/pricing
"""
import httpx
from core.config import get_key
from sources.base import BaseSource


class Hunterhow(BaseSource):
    NAME = 'hunterhow'
    DESCRIPTION = 'Hunter.how — global asset database (EU/APAC coverage)'
    API_TOKEN_IS_REQUIREMENT = True

    _BASE_URL = 'https://api.hunter.how/search'
    _PAGE_SIZE = 100
    _MAX_PAGES = 10

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('hunterhow_key')
        if not api_key:
            return set()

        subdomains: set[str] = set()

        try:
            async with self._make_client() as client:
                for page in range(1, self._MAX_PAGES + 1):
                    params = {
                        'query': f'domain:"{domain}"',
                        'page': page,
                        'page_size': self._PAGE_SIZE,
                        'api-key': api_key,
                    }
                    resp = await self._get(client, self._BASE_URL, params=params)

                    if resp.status_code == 401:
                        self._vlog(1, 'invalid API key')
                        break
                    if resp.status_code == 429:
                        self._vlog(1, 'rate limited')
                        break
                    if resp.status_code != 200:
                        break

                    body = resp.json()
                    if body.get('code') != 200:
                        self._vlog(1, f"API error: {body.get('message', '')}")
                        break

                    assets = body.get('data', {}).get('assets', [])
                    if not assets:
                        break

                    for asset in assets:
                        d = (asset.get('domain') or '').strip().lower()
                        if d:
                            subdomains.add(d)

                    total = body.get('data', {}).get('total', 0)
                    if page * self._PAGE_SIZE >= total:
                        break

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
