"""
URLhaus (abuse.ch) — malicious URL database.

Queries the URLhaus API for all recorded URLs on the target domain and its
subdomains. While the URLs are malicious, the hostnames are real and can
surface subdomains not visible in CT logs or passive DNS.

No API key required.  Reference: https://urlhaus-api.abuse.ch/
"""
import re
from urllib.parse import urlparse

from sources.base import BaseSource

_SUBDOMAIN_RE = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b'
)

_BASE_URL = 'https://urlhaus-api.abuse.ch/v1/host/'


class Urlhaus(BaseSource):
    NAME = 'urlhaus'
    DESCRIPTION = 'URLhaus abuse.ch — malicious URL database (free, no auth)'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()

        try:
            async with self._make_client() as client:
                # URLhaus uses POST with form-encoded body
                resp = await client.post(_BASE_URL, data={'host': domain})
                if self.verbose >= 2:
                    self._vlog(2, f'HTTP {resp.status_code}')
                if resp.status_code == 404:
                    return set()
                if resp.status_code != 200:
                    return set()

                data = resp.json()
                if data.get('query_status') == 'no_results':
                    return set()

                for url_entry in data.get('urls', []):
                    url_str = (url_entry.get('url') or '').strip()
                    if not url_str:
                        continue
                    try:
                        hostname = urlparse(url_str).hostname or ''
                    except Exception:
                        continue
                    if hostname:
                        subdomains.add(hostname.lower())

                    # Also scan any tags/filename fields for additional subdomains
                    for field in ('filename', 'tags'):
                        val = url_entry.get(field) or ''
                        if isinstance(val, list):
                            val = ' '.join(val)
                        for m in _SUBDOMAIN_RE.finditer(val):
                            subdomains.add(m.group(1).lower())

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
