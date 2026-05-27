# -*- coding: utf-8 -*-
"""
DNSDumpster source.

DNSDumpster is a free DNS recon & research tool that discovers hosts related to a domain.
Uses the public web interface (no official public API).

No API key required.
Reference: https://dnsdumpster.com/
"""

import re

import httpx

from sources.base import BaseSource

_BASE_URL = 'https://dnsdumpster.com/'
# Pattern to extract subdomains from HTML table rows
_HOST_RE = re.compile(
    r'<td class="col-md-4">\s*([\w.-]+\.[a-zA-Z]{2,})\s*<br',
    re.IGNORECASE,
)
# Also catch subdomains in the general text blocks
_SUBDOMAIN_RE = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,})\b'
)


class Dnsdumpster(BaseSource):
    NAME = 'dnsdumpster'
    DESCRIPTION = 'DNSDumpster - free DNS recon tool (web scraping)'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()

        headers = {
            'User-Agent': (
                'Mozilla/5.0 (X11; Linux x86_64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/124.0 Safari/537.36'
            ),
            'Referer': _BASE_URL,
            'Origin': 'https://dnsdumpster.com',
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers=headers,
            ) as client:
                # Step 1: GET to obtain CSRF token from cookies / hidden form field
                get_resp = await self._get(client, _BASE_URL)
                if get_resp.status_code != 200:
                    return set()

                # Extract CSRF token from form
                csrf_match = re.search(
                    r'csrfmiddlewaretoken["\s]+value=["\']([^"\']+)["\']',
                    get_resp.text,
                    re.IGNORECASE,
                )
                # Also try cookies
                csrf_token = ''
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                elif 'csrftoken' in client.cookies:
                    csrf_token = client.cookies['csrftoken']

                if not csrf_token:
                    self._vlog(1, 'could not extract CSRF token')
                    return set()

                # Step 2: POST with domain and CSRF token
                post_data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': domain,
                    'user': 'free',
                }
                post_resp = await client.post(
                    _BASE_URL,
                    data=post_data,
                    headers={**headers, 'Content-Type': 'application/x-www-form-urlencoded'},
                )

                if post_resp.status_code not in (200, 302):
                    self._vlog(2, f'POST returned {post_resp.status_code}')
                    return set()

                html = post_resp.text

                # Extract from structured table cells first (more precise)
                for m in _HOST_RE.finditer(html):
                    subdomains.add(m.group(1).lower().rstrip('.'))

                # Fallback: extract all FQDNs from the response HTML
                for m in _SUBDOMAIN_RE.finditer(html):
                    candidate = m.group(1).lower().rstrip('.')
                    if candidate.endswith(f'.{domain}') or candidate == domain:
                        subdomains.add(candidate)

        except Exception as exc:
            self._log_exc(exc)

        return self._filter(subdomains, domain)
