import httpx
from sources.base import BaseSource


class CrtSh(BaseSource):
    NAME = 'crtsh'
    DESCRIPTION = 'Certificate Transparency - crt.sh'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        subdomains: set[str] = set()
        self.timeout = 60.0  # Crt.sh can be slow to respond, increase timeout
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await self._get(client, url)
                if resp.status_code != 200:
                    return subdomains
                for entry in resp.json():
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        subdomains.add(sub.strip())
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
