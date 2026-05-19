import httpx
from sources.base import BaseSource


class CrtSh(BaseSource):
    NAME = 'crtsh'

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains
                for entry in resp.json():
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        subdomains.add(sub.strip())
        except Exception:
            pass
        return self._filter(subdomains, domain)
