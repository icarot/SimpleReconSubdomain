"""
ThreatMiner passive DNS source.

Queries ThreatMiner's domain report endpoint (rt=5) for passive DNS records,
extracting subdomains without requiring an API key.

No API key required.
Reference: https://www.threatminer.org/api.php
"""
from sources.base import BaseSource


class Threatminer(BaseSource):
    NAME = 'threatminer'
    DESCRIPTION = 'ThreatMiner passive DNS - threat intelligence subdomain data'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            async with self._make_client() as client:
                resp = await self._get(
                    client,
                    'https://api.threatminer.org/v2/domain.php',
                    params={'q': domain, 'rt': '5'},
                )
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                # status_code 200 inside JSON means success
                if str(data.get('status_code', '')) != '200':
                    self._vlog(1, f'ThreatMiner: {data.get("status_message", "no results")}')
                    return subdomains
                for entry in data.get('results', []):
                    if isinstance(entry, str) and entry.strip():
                        subdomains.add(entry.strip().lower())
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
