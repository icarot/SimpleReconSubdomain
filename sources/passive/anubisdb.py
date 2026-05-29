from sources.base import BaseSource


class Anubisdb(BaseSource):
    NAME = 'anubisdb'
    DESCRIPTION = 'Anubis-DB - subdomain database by jonlu.ca'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            async with self._make_client() as client:
                resp = await self._get(
                    client, f'https://jonlu.ca/anubis/subdomains/{domain}'
                )
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, str) and entry.strip():
                            subdomains.add(entry.strip().lower())
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
