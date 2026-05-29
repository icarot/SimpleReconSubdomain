"""
HTML link spider (active source).

Crawls the target domain by following <a href> links up to a configurable
depth, extracting subdomain matches from every visited page.

Complements js_scrape (which targets <script src> JS files) by traversing
the full HTML link graph. Because this makes direct HTTP requests to the
target it lives in sources/active/.
"""
import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse

from sources.base import BaseSource

_HREF_RE = re.compile(r'<a[^>]+href=["\']([^"\'#?][^"\']*)["\']', re.IGNORECASE)
_BROWSER_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
}

_MAX_PAGES = 50
_MAX_DEPTH = 2
_CONCURRENCY = 5


class Spider(BaseSource):
    NAME = 'spider'
    DESCRIPTION = 'Active: HTML link crawler — follows <a href> links to discover subdomains'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        subdomain_re = re.compile(
            rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(domain)}',
            re.IGNORECASE,
        )

        # BFS queue: (url, depth)
        queue: deque[tuple[str, int]] = deque()
        visited: set[str] = set()

        async with self._make_client(verify=False, headers=_BROWSER_HEADERS) as client:
            # ── Seed: find the live root URL (https then http) ────────
            root_url = ''
            for scheme in ('https', 'http'):
                try:
                    resp = await asyncio.wait_for(
                        client.get(f'{scheme}://{domain}'),
                        timeout=self.timeout,
                    )
                    if resp.status_code < 500:
                        root_url = str(resp.url)
                        self._extract(resp.text, subdomain_re, subdomains)
                        self._enqueue_links(resp.text, root_url, domain, visited, queue, depth=1)
                        break
                except Exception:
                    continue

            if not root_url:
                return self._filter(subdomains, domain)

            # ── BFS crawl ─────────────────────────────────────────────
            semaphore = asyncio.Semaphore(_CONCURRENCY)

            async def crawl(url: str, depth: int) -> None:
                async with semaphore:
                    try:
                        resp = await asyncio.wait_for(
                            client.get(url),
                            timeout=self.timeout,
                        )
                        if resp.status_code < 400:
                            self._extract(resp.text, subdomain_re, subdomains)
                            if depth < _MAX_DEPTH:
                                self._enqueue_links(
                                    resp.text, str(resp.url), domain, visited, queue, depth + 1
                                )
                    except Exception:
                        pass

            while queue and len(visited) <= _MAX_PAGES:
                batch = []
                while queue and len(batch) < _CONCURRENCY:
                    batch.append(queue.popleft())
                await asyncio.gather(*[crawl(url, d) for url, d in batch])

        return self._filter(subdomains, domain)

    @staticmethod
    def _extract(html: str, pattern: re.Pattern, out: set[str]) -> None:
        for m in pattern.finditer(html):
            out.add(m.group(0).lower())

    @staticmethod
    def _enqueue_links(
        html: str,
        base_url: str,
        domain: str,
        visited: set[str],
        queue: deque,
        depth: int,
    ) -> None:
        for href in _HREF_RE.findall(html):
            url = urljoin(base_url, href)
            parsed = urlparse(url)
            if parsed.scheme not in ('http', 'https'):
                continue
            if domain not in parsed.netloc:
                continue
            canonical = parsed._replace(fragment='', query='').geturl()
            if canonical not in visited:
                visited.add(canonical)
                queue.append((canonical, depth))
