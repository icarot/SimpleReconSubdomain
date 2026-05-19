import httpx
from sources.base import BaseSource
from core.config import get_key


class SecurityTrails(BaseSource):
    NAME = 'securitytrails'
    REQUIRES_API_KEY = True

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('securitytrails')
        if not api_key:
            return set()

        url = f'https://api.securitytrails.com/v1/domain/{domain}/subdomains'
        subdomains: set[str] = set()
        headers = {'APIKEY': api_key}

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, headers=headers
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                for sub in data.get('subdomains', []):
                    subdomains.add(f'{sub}.{domain}')
        except Exception:
            pass
        return self._filter(subdomains, domain)
