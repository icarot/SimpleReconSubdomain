import httpx
from sources.base import BaseSource
from core.config import get_key


class Greynoise(BaseSource):
    NAME = 'greynoise'
    DESCRIPTION = 'GreyNoise - internet scanner rDNS subdomain discovery'
    API_TOKEN_IS_REQUIREMENT = True

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('greynoise_key')
        if not api_key:
            return set()

        headers = {'Authorization': f'Bearer {api_key}'}
        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                offset = 0
                while True:
                    params = {
                        'query': f'metadata.rdns:.{domain}',
                        'limit': 10000,
                        'offset': offset,
                    }
                    resp = await self._get(
                        client,
                        'https://api.greynoise.io/v3/query',
                        params=params,
                        headers=headers,
                    )

                    if resp.status_code == 401:
                        self._vlog(1, 'invalid API key')
                        break
                    if resp.status_code == 429:
                        self._vlog(1, 'rate limit reached')
                        break
                    if resp.status_code != 200:
                        self._vlog(2, f'unexpected status {resp.status_code}')
                        break

                    data = resp.json()
                    entries = data.get('data', [])
                    if not entries:
                        break

                    for entry in entries:
                        rdns = entry.get('metadata', {}).get('rdns', '')
                        if rdns:
                            subdomains.add(rdns.strip().lower().rstrip('.'))

                    if len(entries) < 10000:
                        break
                    offset += len(entries)

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
