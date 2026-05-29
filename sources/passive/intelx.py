import asyncio

from core.config import get_key
from sources.base import BaseSource


class IntelX(BaseSource):
    NAME = 'intelx'
    DESCRIPTION = 'Intelligence X - phonebook subdomain search'
    API_TOKEN_IS_REQUIREMENT = True

    _BASE = 'https://2.intelx.io'

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('intelx_key')
        if not api_key:
            return set()

        subdomains: set[str] = set()

        try:
            async with self._make_client() as client:
                # Step 1: initiate phonebook search
                resp = await client.post(
                    f'{self._BASE}/phonebook/search',
                    params={'k': api_key},
                    json={
                        'term': f'*.{domain}',
                        'buckets': [],
                        'lookuplevel': 0,
                        'maxresults': 100000,
                        'timeout': 0,
                        'datefrom': '',
                        'dateto': '',
                        'sort': 4,
                        'media': 0,
                        'terminate': [],
                        'target': 1,
                    },
                )

                if resp.status_code == 401:
                    self._vlog(1, 'invalid API key')
                    return subdomains
                if resp.status_code != 200:
                    self._vlog(2, f'search initiation failed: {resp.status_code}')
                    return subdomains

                search_id = resp.json().get('id', '')
                if not search_id:
                    return subdomains

                # Brief pause to let the search index
                await asyncio.sleep(2)

                # Step 2: retrieve results
                resp2 = await self._get(
                    client,
                    f'{self._BASE}/phonebook/result',
                    params={
                        'k': api_key,
                        'id': search_id,
                        'limit': 100000,
                        'offset': 0,
                    },
                )

                if resp2.status_code != 200:
                    return subdomains

                data = resp2.json()
                phonebook = data.get('phonebook', data)
                # Response may contain 'domains' list or 'selectors' list
                for entry in phonebook.get('domains', phonebook.get('selectors', [])):
                    if isinstance(entry, str):
                        subdomains.add(entry.strip().lower().lstrip('*.'))
                    elif isinstance(entry, dict):
                        val = entry.get('selectorvalue', '')
                        if val:
                            subdomains.add(val.strip().lower().lstrip('*.'))

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
