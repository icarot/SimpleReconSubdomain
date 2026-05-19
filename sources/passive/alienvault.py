import httpx
from sources.base import BaseSource
from core.config import get_key


class AlienVault(BaseSource):
    NAME = 'alienvault'

    async def fetch(self, domain: str) -> set[str]:
        url = (
            f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
        )
        subdomains: set[str] = set()
        headers = {}
        api_key = get_key('alienvault_otx')
        if api_key:
            headers['X-OTX-API-KEY'] = api_key

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, headers=headers
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains
                for entry in resp.json().get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname:
                        subdomains.add(hostname)
        except Exception:
            pass
        return self._filter(subdomains, domain)
