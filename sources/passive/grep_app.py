import re

import httpx

from sources.base import BaseSource

_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
}


class GrepApp(BaseSource):
    NAME = 'grep_app'
    DESCRIPTION = 'grep.app - code search for subdomain references in public repositories'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        pattern = re.compile(
            rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(domain)}',
            re.IGNORECASE,
        )

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers=_HEADERS,
            ) as client:
                for page in range(1, 6):  # up to 5 pages
                    params = {'q': domain, 'page': page, 'format': 'e'}
                    resp = await self._get(
                        client, 'https://grep.app/api/search', params=params,
                    )
                    
                    if resp.status_code == 429:
                        self._vlog(1, 'rate limit reached')
                        break
                    if resp.status_code != 200:
                        self._vlog(2, f'unexpected status {resp.status_code}')
                        break

                    data = resp.json()
                    hits = data.get('hits', {}).get('hits', [])
                    if not hits:
                        break

                    for hit in hits:
                        snippet_html = hit.get('content', {}).get('snippet', '')
                        for m in pattern.finditer(snippet_html):
                            subdomains.add(m.group(0).lower())

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
