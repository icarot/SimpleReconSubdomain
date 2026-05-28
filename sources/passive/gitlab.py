"""
GitLab code-search source.

Searches GitLab.com public repositories for references to the target domain,
extracting hardcoded subdomains from source files.

API key is optional (higher rate limit with a personal access token).
Add 'gitlab_token' to config/api_keys.json for authenticated requests.

No-auth limit: ~10 req/min. With token: ~600 req/min.
Reference: https://docs.gitlab.com/ee/api/search.html
"""
import re

import httpx

from core.config import get_key
from sources.base import BaseSource

_SUBDOMAIN_RE = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b'
)


class Gitlab(BaseSource):
    NAME = 'gitlab'
    DESCRIPTION = 'GitLab code search for hardcoded domain/subdomain references'
    API_TOKEN_IS_REQUIREMENT = False

    _BASE_URL = 'https://gitlab.com/api/v4/search'
    _MAX_PAGES = 5
    _PER_PAGE = 100

    async def fetch(self, domain: str) -> set[str]:
        token = get_key('gitlab_token')
        headers = {'User-Agent': 'SimpleReconSubdomain/2'}
        if token:
            headers['PRIVATE-TOKEN'] = token

        subdomains: set[str] = set()

        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            for page in range(1, self._MAX_PAGES + 1):
                params = {
                    'scope': 'blobs',
                    'search': domain,
                    'per_page': self._PER_PAGE,
                    'page': page,
                }
                try:
                    resp = await self._get(client, self._BASE_URL, params=params)

                    if resp.status_code == 401:
                        self._vlog(1, 'invalid or missing token')
                        break
                    if resp.status_code == 429:
                        self._vlog(1, 'rate limited')
                        break
                    if resp.status_code != 200:
                        self._vlog(2, f'HTTP {resp.status_code}')
                        break

                    items = resp.json()
                    if not items:
                        break

                    for item in items:
                        # data field contains the matched file content fragment
                        blob_data = item.get('data', '') or ''
                        filename = item.get('filename', '') or ''
                        for text in (blob_data, filename):
                            for m in _SUBDOMAIN_RE.finditer(text):
                                candidate = m.group(1).lower()
                                if candidate.endswith(f'.{domain}') or candidate == domain:
                                    subdomains.add(candidate)

                    if len(items) < self._PER_PAGE:
                        break

                except Exception as e:
                    self._log_exc(e)
                    break

        return self._filter(subdomains, domain)
