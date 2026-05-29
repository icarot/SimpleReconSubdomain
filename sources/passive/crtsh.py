from sources.base import BaseSource


class CrtSh(BaseSource):
    NAME = 'crtsh'
    DESCRIPTION = 'Certificate Transparency - crt.sh'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        subdomains: set[str] = set()
        _timeout = max(self.timeout, 60.0)  # crt.sh can be slow; never go below 60s
        try:
            async with self._make_client(timeout=_timeout) as client:
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
