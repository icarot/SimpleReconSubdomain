import re

from core.config import get_key
from sources.base import BaseSource


class Publicwww(BaseSource):
    NAME = 'publicwww'
    DESCRIPTION = 'PublicWWW - website source code search for subdomain references'
    API_TOKEN_IS_REQUIREMENT = True

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('publicwww_key')
        if not api_key:
            return set()

        subdomains: set[str] = set()
        pattern = re.compile(
            rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(domain)}',
            re.IGNORECASE,
        )

        try:
            async with self._make_client() as client:
                resp = await self._get(
                    client,
                    f'https://publicwww.com/websites/%22.{domain}%22/',
                    params={'export': 'csv', 'k': api_key},
                )

                if resp.status_code == 401:
                    self._vlog(1, 'invalid API key')
                    return subdomains
                if resp.status_code != 200:
                    self._vlog(2, f'unexpected status {resp.status_code}')
                    return subdomains

                for line in resp.text.splitlines():
                    for m in pattern.finditer(line):
                        subdomains.add(m.group(0).lower())

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
