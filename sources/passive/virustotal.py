import httpx
from sources.base import BaseSource
from core.config import get_key


class VirusTotal(BaseSource):
    NAME = 'virustotal'
    DESCRIPTION = 'VirusTotal subdomains'
    API_TOKEN_IS_REQUIREMENT = True

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('virustotal')
        if not api_key:
            return set()

        url = f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains'
        subdomains: set[str] = set()
        headers = {'x-apikey': api_key}

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, headers=headers
            ) as client:
                cursor = None
                while True:
                    params: dict = {'limit': 40}
                    if cursor:
                        params['cursor'] = cursor
                    resp = await self._get(client, url, params=params)
                    if resp.status_code != 200:
                        break
                    data = resp.json()
                    for entry in data.get('data', []):
                        subdomains.add(entry.get('id', ''))
                    cursor = data.get('meta', {}).get('cursor')
                    if not cursor:
                        break
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
