"""
MerkleMap Certificate Transparency source.

Queries MerkleMap's CT log aggregator as an alternative to crt.sh.
Covers some logs not indexed by crt.sh.

MerkleMap migrated entirely to /v1/search which requires a paid subscription.
Set 'merklemap_key' in config/api_keys.json with a valid subscription token.

Reference: https://www.merklemap.com/documentation/search
"""
import httpx

from core.config import get_key
from sources.base import BaseSource


class Merklemap(BaseSource):
    NAME = 'merklemap'
    DESCRIPTION = 'MerkleMap CT log aggregator - alternative to crt.sh'
    API_TOKEN_IS_REQUIREMENT = True

    _BASE_URL = 'https://api.merklemap.com/v1/search'
    _MAX_PAGES = 10

    async def fetch(self, domain: str) -> set[str]:
        token = get_key('merklemap_key')
        if not token:
            return set()

        subdomains: set[str] = set()
        headers = {'Authorization': f'Bearer {token}'}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers=headers,
            ) as client:
                for page in range(self._MAX_PAGES):
                    resp = await self._get(
                        client,
                        self._BASE_URL,
                        params={'query': domain, 'page': page, 'type': 'distance'},
                    )

                    if resp.status_code in (401, 403):
                        self._vlog(1, f'auth failed (HTTP {resp.status_code}) — subscription required')
                        break
                    if resp.status_code == 429:
                        self._vlog(1, 'rate limited')
                        break
                    if resp.status_code != 200:
                        break

                    try:
                        data = resp.json()
                    except Exception:
                        break

                    results = data.get('results', [])
                    if not results:
                        break
                    for entry in results:
                        if isinstance(entry, str):
                            subdomains.add(entry.strip().lower())
                            continue
                        for key in ('domain', 'hostname', 'name', 'subdomain'):
                            val = entry.get(key, '')
                            if val:
                                subdomains.add(val.strip().lower())
                                break

                    if not data.get('next') and not data.get('has_more'):
                        break
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
