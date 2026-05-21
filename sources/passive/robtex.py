import json
import httpx
from sources.base import BaseSource


class Robtex(BaseSource):
    NAME = 'robtex'
    DESCRIPTION = 'Robtex passive DNS'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://freeapi.robtex.com/pdns/forward/{domain}'
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await self._get(client, url)
                if resp.status_code != 200:
                    return subdomains
                # Response is newline-delimited JSON
                for line in resp.text.splitlines():
                    try:
                        entry = json.loads(line)
                        rrname = entry.get('rrname', '')
                        if rrname:
                            subdomains.add(rrname.rstrip('.'))
                    except (json.JSONDecodeError, KeyError):
                        pass
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
