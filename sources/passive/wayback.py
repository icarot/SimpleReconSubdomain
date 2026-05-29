from sources.base import BaseSource


class Wayback(BaseSource):
    NAME = 'wayback'
    DESCRIPTION = 'Wayback Machine (web.archive.org)'
    API_TOKEN_IS_REQUIREMENT = False

    _BASE_URL = 'http://web.archive.org/cdx/search/cdx'
    _PARAMS_BASE = {
        'output': 'text',
        'fl': 'original',
        'collapse': 'urlkey',
        'limit': '10000',
    }

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        self.timeout = 50.0  # Wayback can be slow to respond

        async with self._make_client() as client:
            # Discover total number of CDX pages for this query
            try:
                count_resp = await self._get(
                    client,
                    self._BASE_URL,
                    params={**self._PARAMS_BASE, 'url': f'*.{domain}', 'showNumPages': 'true'},
                )
                num_pages = 1
                if count_resp.status_code == 200:
                    raw = count_resp.text.strip()
                    if raw.isdigit():
                        num_pages = max(1, int(raw))
            except Exception as e:
                self._log_exc(e)
                num_pages = 1

            # Cap at a sensible number of pages to avoid very long scans
            num_pages = min(num_pages, 20)

            for page in range(num_pages):
                try:
                    resp = await self._get(
                        client,
                        self._BASE_URL,
                        params={**self._PARAMS_BASE, 'url': f'*.{domain}', 'page': str(page)},
                    )
                    if resp.status_code != 200:
                        break
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if '://' in line:
                            host = line.split('://')[1].split('/')[0].split(':')[0]
                            subdomains.add(host)
                    if not resp.text.strip():
                        break
                except Exception as e:
                    self._log_exc(e)
                    break

        return self._filter(subdomains, domain)
