import httpx
from sources.base import BaseSource
from core.config import get_key


class SecurityTrails(BaseSource):
    NAME = 'securitytrails'
    DESCRIPTION = 'SecurityTrails DNS history'
    API_TOKEN_IS_REQUIREMENT = True

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
                resp = await self._get(client, url)
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                for sub in data.get('subdomains', []):
                    subdomains.add(f'{sub}.{domain}')
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
