# -*- coding: utf-8 -*-
"""
GitHub code-search source.

Searches GitHub for code references to the target domain, extracting
hardcoded subdomains found in source files (configs, env files, scripts, etc.).

Requires a GitHub personal access token (scope: public_repo or repo).
Add 'github_token' to config/api_keys.json.
"""

import re

from core.config import get_key
from sources.base import BaseSource

_SUBDOMAIN_RE = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b'
)


class Github(BaseSource):
    NAME = 'github'
    DESCRIPTION = 'GitHub code search for hardcoded domain/subdomain references'
    API_TOKEN_IS_REQUIREMENT = True

    # GitHub Search API: up to 10 pages × 100 results = 1000 code items
    _BASE_URL = 'https://api.github.com/search/code'
    _MAX_PAGES = 10
    _PER_PAGE = 100

    async def fetch(self, domain: str) -> set[str]:
        token = get_key('github_token')
        if not token:
            return set()

        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3.text-match+json',
            'User-Agent': 'SimpleReconSubdomain/2',
            'X-GitHub-Api-Version': '2022-11-28',
        }

        subdomains: set[str] = set()

        async with self._make_client(headers=headers) as client:
            for page in range(1, self._MAX_PAGES + 1):
                params = {
                    'q': domain,
                    'per_page': self._PER_PAGE,
                    'page': page,
                }
                try:
                    resp = await self._get(client, self._BASE_URL, params=params)

                    if resp.status_code == 422:
                        # Unprocessable entity — query not accepted, stop early
                        break
                    if resp.status_code == 403:
                        # Rate limit hit
                        self._vlog(1, 'rate limit reached; stopping pagination')
                        break
                    if resp.status_code != 200:
                        self._vlog(2, f'unexpected status {resp.status_code}')
                        break

                    data = resp.json()
                    items = data.get('items', [])
                    if not items:
                        break

                    for item in items:
                        # Extract from text_matches snippets (richer content)
                        for match in item.get('text_matches', []):
                            fragment = match.get('fragment', '')
                            for m in _SUBDOMAIN_RE.finditer(fragment):
                                subdomains.add(m.group(1).lower())

                        # Also extract from the repository URL and file path
                        for field in ('html_url', 'path', 'name'):
                            val = item.get(field, '')
                            for m in _SUBDOMAIN_RE.finditer(val):
                                subdomains.add(m.group(1).lower())

                    # GitHub caps search results at 1000 total; stop if last page
                    total_count = data.get('total_count', 0)
                    if page * self._PER_PAGE >= min(total_count, 1000):
                        break

                except Exception as exc:
                    self._log_exc(exc)
                    break

        return self._filter(subdomains, domain)
