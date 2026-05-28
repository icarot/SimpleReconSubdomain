import httpx

from core.config import get_key
from sources.base import BaseSource


class Pulsedive(BaseSource):
    NAME = 'pulsedive'
    DESCRIPTION = 'Pulsedive - threat intelligence indicator exploration'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('pulsedive_key')

        params: dict = {'q': f'domain={domain}', 'limit': 1000, 'pretty': 1}
        if api_key:
            params['key'] = api_key

        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await self._get(
                    client,
                    'https://pulsedive.com/api/explore.php',
                    params=params,
                )

                if resp.status_code == 429:
                    self._vlog(1, 'rate limit reached — provide pulsedive_key for higher limits')
                    return subdomains
                if resp.status_code != 200:
                    self._vlog(2, f'unexpected status {resp.status_code}')
                    return subdomains

                data = resp.json()
                # API returns 'indicators' list; older versions used 'results'
                for entry in data.get('indicators', data.get('results', [])):
                    val = entry.get('value', entry.get('indicator', ''))
                    itype = entry.get('type', '')
                    if itype == 'domain' and val:
                        subdomains.add(val.strip().lower())

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
