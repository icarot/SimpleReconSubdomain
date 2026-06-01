"""
JavaScript link extraction (active source).

Fetches the root domain's HTML page, discovers all linked .js files via
BeautifulSoup (<script src> and <link rel=preload as=script>), downloads
each script, extracts subdomains via regex, and follows sourcemap references
(//# sourceMappingURL or X-SourceMap header) to also mine .map files.

Because this makes direct HTTP requests to the target, it lives in
sources/active/.
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from sources.base import BaseSource

_BROWSER_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
}

_JS_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0'
    ),
    'Accept': '*/*',
    'Sec-Fetch-Dest': 'script',
    'Sec-Fetch-Mode': 'no-cors',
}

# Max JS / .map files to download per domain (avoid unbounded crawls)
_MAX_JS_FILES = 30
_MAX_MAP_FILES = 20

# Matches: //# sourceMappingURL=<path>  or  //@ sourceMappingURL=<path>
_MAP_COMMENT_RE = re.compile(
    r'//[#@]\s*sourceMappingURL=([^\s\'"]+)', re.IGNORECASE
)


class JsScrape(BaseSource):
    NAME = 'js_scrape'
    DESCRIPTION = 'Active: JS link extraction — discovers subdomains hardcoded in JS bundles and source maps'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        subdomain_re = re.compile(
            rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(domain)}',
            re.IGNORECASE,
        )

        async with self._make_client(verify=False, headers=_BROWSER_HEADERS) as client:
            # ── Step 1: fetch root page (try https then http) ──────────
            root_html = ''
            base_url = ''
            for scheme in ('https', 'http'):
                try:
                    resp = await asyncio.wait_for(
                        client.get(f'{scheme}://{domain}'),
                        timeout=self.timeout,
                    )
                    if resp.status_code < 500:
                        root_html = resp.text
                        base_url = str(resp.url)
                        for m in subdomain_re.finditer(root_html):
                            subdomains.add(m.group(0).lower())
                        break
                except Exception:
                    continue

            if not root_html:
                return self._filter(subdomains, domain)

            # ── Step 2: collect JS URLs via BeautifulSoup ─────────────
            soup = BeautifulSoup(root_html, 'html.parser')
            raw_js: list[str] = []

            for tag in soup.find_all('script', src=True):
                src = tag.get('src', '')
                if src:
                    raw_js.append(src)

            for tag in soup.find_all('link', href=True):
                rel = ' '.join(tag.get('rel', []))
                as_attr = tag.get('as', '')
                href = tag.get('href', '')
                if href and ('script' in as_attr or 'modulepreload' in rel):
                    raw_js.append(href)

            js_urls: list[str] = []
            seen: set[str] = set()
            for src in raw_js:
                url = urljoin(base_url, src)
                parsed = urlparse(url)
                if parsed.scheme not in ('http', 'https'):
                    continue
                if domain not in parsed.netloc:
                    continue
                if url not in seen:
                    seen.add(url)
                    js_urls.append(url)

            js_urls = js_urls[:_MAX_JS_FILES]
            if not js_urls:
                return self._filter(subdomains, domain)

            # ── Step 3: download JS, extract subdomains + map refs ────
            map_urls: list[str] = []
            map_seen: set[str] = set()
            semaphore = asyncio.Semaphore(5)

            def _collect_map(js_url: str, body: str, headers: dict) -> None:
                # Header-based sourcemap reference
                map_ref = headers.get('x-sourcemap') or headers.get('sourcemap', '')
                if not map_ref:
                    # Comment-based sourcemap reference (last match wins)
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
                        js_resp = await asyncio.wait_for(
                            client.get(url, headers=_JS_HEADERS),
                            timeout=self.timeout,
                        )
                        if js_resp.status_code == 200:
                            body = js_resp.text
                            for m in subdomain_re.finditer(body):
                                subdomains.add(m.group(0).lower())
                            _collect_map(url, body, dict(js_resp.headers))
                    except Exception:
                        pass

            await asyncio.gather(*[fetch_js(u) for u in js_urls])

            # ── Step 4: download .map files and extract subdomains ────
            async def fetch_map(url: str) -> None:
                async with semaphore:
                    try:
                        map_resp = await asyncio.wait_for(
                            client.get(url, headers=_JS_HEADERS),
                            timeout=self.timeout,
                        )
                        if map_resp.status_code == 200:
                            for m in subdomain_re.finditer(map_resp.text):
                                subdomains.add(m.group(0).lower())
                    except Exception:
                        pass

            if map_urls:
                await asyncio.gather(*[fetch_map(u) for u in map_urls[:_MAX_MAP_FILES]])

        return self._filter(subdomains, domain)
