# -*- coding: utf-8 -*-
"""
ProjectDiscovery Chaos Dataset source.

Chaos is a continuously updated subdomain dataset maintained by ProjectDiscovery.
It provides verified subdomains for thousands of bug bounty programs and public domains.

Requires a Chaos API key. Sign up at: https://chaos.projectdiscovery.io/
Add 'chaos_key' to config/api_keys.json.
"""

import httpx

from core.config import get_key
from sources.base import BaseSource


class Chaos(BaseSource):
    NAME = 'chaos'
    DESCRIPTION = 'ProjectDiscovery Chaos dataset - continuously updated subdomain DB'
    API_TOKEN_IS_REQUIREMENT = True

    _BASE_URL = 'https://dns.projectdiscovery.io/dns/{domain}/subdomains'

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('chaos_key')
        if not api_key:
            return set()

        headers = {
            'Authorization': api_key,
        }

        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await self._get(
                    client,
                    self._BASE_URL.format(domain=domain),
                    headers=headers,
                )

                if resp.status_code == 401:
                    self._vlog(1, 'invalid or expired API key')
                    return set()
                if resp.status_code == 404:
                    # Domain not in Chaos DB
                    self._vlog(1, f'{domain} not found in Chaos DB')
                    return set()
                if resp.status_code != 200:
                    self._vlog(2, f'unexpected status {resp.status_code}')
                    return set()

                data = resp.json()

                # Response: {"domain": "example.com", "subdomains": ["api", "dev", ...], "count": N}
                # Subdomains are returned as prefixes only
                root = data.get('domain', domain)
                for prefix in data.get('subdomains', []):
                    if prefix:
                        subdomains.add(f'{prefix.strip().lower()}.{root}')

        except Exception as exc:
            self._log_exc(exc)

        return self._filter(subdomains, domain)
