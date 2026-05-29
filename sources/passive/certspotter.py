from sources.base import BaseSource


class CertSpotter(BaseSource):
    NAME = 'certspotter'
    DESCRIPTION = 'Certificate Transparency - CertSpotter'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        url = (
            f'https://api.certspotter.com/v1/issuances'
            f'?domain={domain}&expand=dns_names&include_subdomains=true'
        )
        subdomains: set[str] = set()
        try:
            async with self._make_client() as client:
                resp = await self._get(client, url)
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                if isinstance(data, list):
                    for entry in data:
                        for name in entry.get('dns_names', []):
                            subdomains.add(name)
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
