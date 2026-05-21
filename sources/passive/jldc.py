import httpx
from sources.base import BaseSource


class JLDC(BaseSource):
    NAME = 'jldc'
    DESCRIPTION = 'Anubis / JLDC subdomain DB'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://jldc.me/anubis/subdomains/{domain}'
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await self._get(client, url)
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                if isinstance(data, list):
                    subdomains.update(data)
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
