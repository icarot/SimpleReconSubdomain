import httpx
from sources.base import BaseSource
from core.config import get_key


class HackerTarget(BaseSource):
    NAME = 'hackertarget'
    DESCRIPTION = 'HackerTarget host search'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        params: dict = {'q': domain}
        api_key = get_key('hackertarget')
        if api_key:
            params['apikey'] = api_key

        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await self._get(client, 'https://api.hackertarget.com/hostsearch/', params=params)
                if resp.status_code != 200:
                    return subdomains
                for line in resp.text.splitlines():
                    parts = line.split(',')
                    if parts:
                        subdomains.add(parts[0].strip())
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
