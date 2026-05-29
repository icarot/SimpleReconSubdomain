# -*- coding: utf-8 -*-
"""
Common Crawl CDX API source.

Queries the latest available Common Crawl index for all URLs under *.{domain},
then extracts hostnames. Complements the Wayback Machine with independent crawl data.

No API key required.
Reference: https://index.commoncrawl.org/
"""

import json
from urllib.parse import urlparse

from sources.base import BaseSource

_INDEX_URL = 'https://index.commoncrawl.org/collinfo.json'
# Note: Common Crawl CDX endpoint requires the '-index' suffix after the collection ID
_CDX_TEMPLATE = 'https://index.commoncrawl.org/{index}-index?url=*.{domain}&output=json&limit=5000&fl=url&collapse=urlkey'


class Commoncrawl(BaseSource):
    NAME = 'commoncrawl'
    DESCRIPTION = 'Common Crawl CDX API - historical web crawl URL index'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()

        async with self._make_client() as client:
            # Step 1: fetch list of available indexes and pick the most recent one
            try:
                resp = await self._get(client, _INDEX_URL)
                if resp.status_code != 200:
                    return set()
                indexes = resp.json()
                if not indexes:
                    return set()
                # indexes are listed newest-first
                latest_id = indexes[0].get('id', '')
                if not latest_id:
                    return set()
            except Exception as exc:
                self._log_exc(exc)
                return set()

            # Step 2: query CDX for all URLs under *.domain
            cdx_url = _CDX_TEMPLATE.format(index=latest_id, domain=domain)
            try:
                resp = await self._get(client, cdx_url)
                if resp.status_code != 200:
                    return set()

                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        url = entry.get('url', '')
                    except (json.JSONDecodeError, AttributeError):
                        # Some CDX endpoints return plain text lines
                        url = line

                    if not url:
                        continue
                    try:
                        parsed = urlparse(url if '://' in url else f'http://{url}')
                        host = parsed.hostname or ''
                        if host:
                            subdomains.add(host.lower().rstrip('.'))
                    except Exception:
                        pass

            except Exception as exc:
                self._log_exc(exc)

        return self._filter(subdomains, domain)
