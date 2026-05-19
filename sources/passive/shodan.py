import httpx
from sources.base import BaseSource
from core.config import get_key


class Shodan(BaseSource):
    NAME = 'shodan'
    REQUIRES_API_KEY = True

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('shodan')
        if not api_key:
            return set()

        url = f'https://api.shodan.io/dns/domain/{domain}'
        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                resp = await client.get(url, params={'key': api_key})
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                # Campo 'subdomains' contém apenas os prefixos (ex: "www", "mail")
                for prefix in data.get('subdomains', []):
                    subdomains.add(f'{prefix}.{domain}')
        except Exception:
            pass

        return self._filter(subdomains, domain)
