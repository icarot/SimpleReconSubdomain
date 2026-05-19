import httpx
from sources.base import BaseSource


class JLDC(BaseSource):
    NAME = 'jldc'

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://jldc.me/anubis/subdomains/{domain}'
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                if isinstance(data, list):
                    subdomains.update(data)
        except Exception:
            pass
        return self._filter(subdomains, domain)
