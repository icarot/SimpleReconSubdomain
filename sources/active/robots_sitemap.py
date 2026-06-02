"""
robots.txt + sitemap.xml hostname extraction (active source).

Phase 1 — Fetches /robots.txt: extracts Sitemap: directives and any hostnames
           embedded in Disallow: paths.
Phase 2 — Fetches each sitemap URL found (supports <sitemapindex> nesting up to
           _MAX_DEPTH levels and _MAX_SITEMAPS total fetches).
Phase 3 — Parses <loc> entries in every sitemap and extracts hostnames.

Because this makes direct HTTP requests to the target it lives in sources/active/.
"""
import asyncio
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from sources.base import BaseSource

_MAX_SITEMAPS = 20
_MAX_DEPTH    = 2

_RE_SITEMAP = re.compile(r'^Sitemap:\s*(\S+)', re.IGNORECASE | re.MULTILINE)
_RE_DISALLOW = re.compile(r'^(?:Disallow|Allow):\s*(\S+)', re.IGNORECASE | re.MULTILINE)


def _hostname(url: str) -> str | None:
    try:
        h = urlparse(url.strip()).hostname or ''
        return h.lower() or None
    except Exception:
        return None


class Robots_sitemap(BaseSource):
    NAME = 'robots_sitemap'
    DESCRIPTION = 'Active: robots.txt directives + sitemap.xml <loc> hostname extraction'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        sitemap_queue: list[tuple[str, int]] = []   # (url, depth)
        visited_sitemaps: set[str] = set()

        async with self._make_client(verify=False) as client:
            # ── Phase 1: robots.txt ───────────────────────────────────
            for scheme in ('https', 'http'):
                try:
                    resp = await asyncio.wait_for(
                        client.get(f'{scheme}://{domain}/robots.txt'),
                        timeout=self.timeout,
                    )
                    if resp.status_code == 200:
                        body = resp.text

                        # Sitemap: directives
                        for m in _RE_SITEMAP.finditer(body):
                            url = m.group(1).strip()
                            if url not in visited_sitemaps:
                                sitemap_queue.append((url, 1))

                        # Hostnames leaked in Disallow/Allow paths
                        for m in _RE_DISALLOW.finditer(body):
                            path = m.group(1)
                            if path.startswith(('http://', 'https://')):
                                h = _hostname(path)
                                if h:
                                    subdomains.add(h)
                        break
                except Exception:
                    continue

            # If no Sitemap: in robots.txt, try common locations
            if not sitemap_queue:
                for candidate in (
                    f'https://{domain}/sitemap.xml',
                    f'https://{domain}/sitemap_index.xml',
                    f'https://{domain}/sitemaps/sitemap.xml',
                ):
                    sitemap_queue.append((candidate, 1))

            # ── Phase 2 & 3: fetch + parse sitemaps ──────────────────
            fetched = 0
            while sitemap_queue and fetched < _MAX_SITEMAPS:
                url, depth = sitemap_queue.pop(0)
                if url in visited_sitemaps:
                    continue
                visited_sitemaps.add(url)
                fetched += 1

                try:
                    resp = await asyncio.wait_for(
                        client.get(url),
                        timeout=self.timeout,
                    )
                    if resp.status_code != 200:
                        continue

                    soup = BeautifulSoup(resp.text, 'html.parser')

                    # <sitemapindex> — links to more sitemaps
                    if depth < _MAX_DEPTH:
                        for loc in soup.find_all('sitemap'):
                            child_loc = loc.find('loc')
                            if child_loc and child_loc.text.strip():
                                child_url = child_loc.text.strip()
                                if child_url not in visited_sitemaps:
                                    sitemap_queue.append((child_url, depth + 1))

                    # <urlset> — actual page URLs
                    for loc in soup.find_all('loc'):
                        loc_url = loc.text.strip()
                        if not loc_url:
                            continue
                        # Skip nested sitemap locs (already handled above)
                        if loc.parent and loc.parent.name == 'sitemap':
                            continue
                        h = _hostname(loc_url)
                        if h:
                            subdomains.add(h)

                except Exception:
                    continue

        self._vlog(1, f'fetched {fetched} sitemap(s), {len(subdomains)} raw hostnames')
        return self._filter(subdomains, domain)
