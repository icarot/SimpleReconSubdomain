# -*- coding: utf-8 -*-
"""
Netlas.io source.

Netlas is an internet-wide asset discovery engine that indexes hosts, domains,
certificates, and other internet infrastructure data.

Requires a Netlas API key. Sign up at: https://app.netlas.io/
Add 'netlas_key' to config/api_keys.json.
"""

from core.config import get_key
from sources.base import BaseSource


class Netlas(BaseSource):
    NAME = 'netlas'
    DESCRIPTION = 'Netlas.io - internet-wide asset and subdomain discovery engine'
    API_TOKEN_IS_REQUIREMENT = True

    # Domains endpoint: search for DNS records matching *.domain
    _BASE_URL = 'https://app.netlas.io/api/domains/'
    _PAGE_SIZE = 200

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('netlas_key')
        if not api_key:
            return set()

        headers = {
            'X-API-Key': api_key,
        }

        subdomains: set[str] = set()

        params = {
            'q': f'domain:*.{domain}',
            'fields': 'domain',
            'size': self._PAGE_SIZE,
            'start': 0,
        }

        try:
            async with self._make_client() as client:
                # Paginate until no more results
                while True:
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
                    items = data.get('items', [])
                    if not items:
                        break

                    for item in items:
                        # Each item has a 'data' dict with a 'domain' field
                        sub = (
                            item.get('data', {}).get('domain', '')
                            or item.get('domain', '')
                        )
                        if sub:
                            subdomains.add(sub.strip().lower().rstrip('.'))

                    # Stop if we received fewer items than the page size
                    if len(items) < self._PAGE_SIZE:
                        break

                    params['start'] += self._PAGE_SIZE

        except Exception as exc:
            self._log_exc(exc)

        return self._filter(subdomains, domain)
