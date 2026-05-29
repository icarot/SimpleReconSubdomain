# -*- coding: utf-8 -*-
"""
C99 Subdomain Finder source.

C99.nl provides a subdomain lookup API with a comprehensive subdomain database.

Requires a C99 API key. Sign up at: https://api.c99.nl/
Add 'c99_key' to config/api_keys.json.
"""

from core.config import get_key
from sources.base import BaseSource


class C99(BaseSource):
    NAME = 'c99'
    DESCRIPTION = 'C99.nl subdomain finder API'
    API_TOKEN_IS_REQUIREMENT = True

    _BASE_URL = 'https://api.c99.nl/subdomainfinder'

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('c99_key')
        if not api_key:
            return set()

        subdomains: set[str] = set()

        params = {
            'key': api_key,
            'domain': domain,
            'json': '',
        }

        try:
            async with self._make_client() as client:
                resp = await self._get(client, self._BASE_URL, params=params)

                if resp.status_code == 401:
                    self._vlog(1, 'invalid API key')
                    return set()
                if resp.status_code != 200:
                    self._vlog(2, f'unexpected status {resp.status_code}')
                    return set()

                data = resp.json()

                # Response format: {"status": "success", "subdomains": [...]}
                # Each entry may be a string or a dict with a 'subdomain' key
                if not data.get('status', '').lower().startswith('success'):
                    error_msg = data.get('error', 'unknown error')
                    self._vlog(1, f'API error: {error_msg}')
                    return set()

                for entry in data.get('subdomains', []):
                    if isinstance(entry, str):
                        subdomains.add(entry.strip().lower())
                    elif isinstance(entry, dict):
                        sub = entry.get('subdomain', '') or entry.get('host', '') or entry.get('hostname', '')
                        if sub:
                            subdomains.add(sub.strip().lower())

        except Exception as exc:
            self._log_exc(exc)

        return self._filter(subdomains, domain)
