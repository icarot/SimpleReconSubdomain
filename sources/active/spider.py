"""
HTML + JS spider (active source).

Phase 1 — Fetches the root page (https then http fallback).
Phase 2 — BFS crawl: follows <a href> and <link href> up to _MAX_DEPTH,
           collecting <script src> and <link preload as=script> into a
           separate JS queue along the way.
Phase 3 — Downloads each JS file; extracts subdomains and discovers
           sourcemap references (X-SourceMap header or //# sourceMappingURL).
Phase 4 — Downloads .map files and extracts subdomains from their content.

This replaces the separate js_scrape source, which covered steps 3-4 but
duplicated the root-page fetch and HTML parsing.

Because this makes direct HTTP requests to the target it lives in sources/active/.
"""
import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from sources.base import BaseSource

_BROWSER_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
}

_JS_HEADERS = {
    'Accept': '*/*',
    'Sec-Fetch-Dest': 'script',
    'Sec-Fetch-Mode': 'no-cors',
}

_MAX_PAGES     = 100
_MAX_DEPTH     = 3
_CONCURRENCY   = 5
_MAX_JS_FILES  = 40
_MAX_MAP_FILES = 30

_MAP_COMMENT_RE = re.compile(
    r'//[#@]\s*sourceMappingURL=([^\s\'"]+)', re.IGNORECASE
)


class Spider(BaseSource):
    NAME = 'spider'
    DESCRIPTION = (
        'Active: HTML crawler + JS/sourcemap miner — '
        'follows links, downloads JS bundles and .map files'
    )
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        subdomain_re = re.compile(
            rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(domain)}',
            re.IGNORECASE,
        )

        # BFS state
        page_queue: deque[tuple[str, int]] = deque()
        visited: set[str] = set()   # dedup — prevents the same URL being enqueued twice
        fetched: int = 0            # counts actually completed HTTP requests

        # JS collection (populated during BFS)
        js_urls: list[str] = []
        js_seen: set[str] = set()

        async with self._make_client(verify=False, headers=_BROWSER_HEADERS) as client:
            # ── Phase 1: seed from root URL ───────────────────────────
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
                        self._enqueue_links(resp.text, root_url, domain, visited, page_queue, depth=1)
                        self._collect_js(resp.text, root_url, domain, js_seen, js_urls)
                        break
                except Exception:
                    continue

            if not root_url:
                return self._filter(subdomains, domain)

            # ── Phase 2: BFS crawl ────────────────────────────────────
            semaphore = asyncio.Semaphore(_CONCURRENCY)

            async def crawl(url: str, depth: int) -> None:
                nonlocal fetched
                async with semaphore:
                    try:
                        resp = await asyncio.wait_for(
                            client.get(url),
                            timeout=self.timeout,
                        )
                        fetched += 1
                        if resp.status_code < 400:
                            html = resp.text
                            actual_url = str(resp.url)
                            self._extract(html, subdomain_re, subdomains)
                            self._collect_js(html, actual_url, domain, js_seen, js_urls)
                            if depth < _MAX_DEPTH:
                                self._enqueue_links(
                                    html, actual_url, domain, visited, page_queue, depth + 1
                                )
                    except Exception:
                        pass

            while page_queue and fetched < _MAX_PAGES:
                batch: list[tuple[str, int]] = []
                while page_queue and len(batch) < _CONCURRENCY:
                    batch.append(page_queue.popleft())
                await asyncio.gather(*[crawl(url, d) for url, d in batch])

            # ── Phase 3: download JS files ────────────────────────────
            map_urls: list[str] = []
            map_seen: set[str] = set()

            def _register_map(js_url: str, body: str, headers: dict) -> None:
                map_ref = headers.get('x-sourcemap') or headers.get('sourcemap', '')
                if not map_ref:
                    matches = _MAP_COMMENT_RE.findall(body)
                    map_ref = matches[-1] if matches else ''
                if map_ref and not map_ref.startswith('data:'):
                    map_url = urljoin(js_url, map_ref)
                    if map_url not in map_seen:
                        map_seen.add(map_url)
                        map_urls.append(map_url)

            async def fetch_js(url: str) -> None:
                async with semaphore:
                    try:
                        resp = await asyncio.wait_for(
                            client.get(url, headers=_JS_HEADERS),
                            timeout=self.timeout,
                        )
                        if resp.status_code == 200:
                            body = resp.text
                            self._extract(body, subdomain_re, subdomains)
                            _register_map(url, body, dict(resp.headers))
                    except Exception:
                        pass

            await asyncio.gather(*[fetch_js(u) for u in js_urls[:_MAX_JS_FILES]])

            # ── Phase 4: download .map files ──────────────────────────
            async def fetch_map(url: str) -> None:
                async with semaphore:
                    try:
                        resp = await asyncio.wait_for(
                            client.get(url, headers=_JS_HEADERS),
                            timeout=self.timeout,
                        )
                        if resp.status_code == 200:
                            self._extract(resp.text, subdomain_re, subdomains)
                    except Exception:
                        pass

            if map_urls:
                await asyncio.gather(*[fetch_map(u) for u in map_urls[:_MAX_MAP_FILES]])

            # Expose crawled URLs as extras
            self.extras['urls'].update(visited)
            self.extras['urls'].update(js_urls[:_MAX_JS_FILES])
            self.extras['urls'].update(map_urls[:_MAX_MAP_FILES])

        return self._filter(subdomains, domain)

    # ── Static helpers ────────────────────────────────────────────────

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
        soup = BeautifulSoup(html, 'html.parser')
        hrefs: list[str] = []
        for tag in soup.find_all('a', href=True, limit=500):
            hrefs.append(tag['href'])
        for tag in soup.find_all('link', href=True, limit=100):
            hrefs.append(tag['href'])
        for href in hrefs:
            if not href or len(href) <= 3:
                continue
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

    @staticmethod
    def _collect_js(
        html: str,
        base_url: str,
        domain: str,
        seen: set[str],
        out: list[str],
    ) -> None:
        soup = BeautifulSoup(html, 'html.parser')
        raw: list[str] = []
        for tag in soup.find_all('script', src=True):
            src = tag.get('src', '')
            if src:
                raw.append(src)
        for tag in soup.find_all('link', href=True):
            rel = ' '.join(tag.get('rel', []))
            as_attr = tag.get('as', '')
            href = tag.get('href', '')
            if href and ('script' in as_attr or 'modulepreload' in rel):
                raw.append(href)
        for src in raw:
            url = urljoin(base_url, src)
            parsed = urlparse(url)
            if parsed.scheme not in ('http', 'https'):
                continue
            if domain not in parsed.netloc:
                continue
            if url not in seen:
                seen.add(url)
                out.append(url)
