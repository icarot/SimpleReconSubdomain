"""
JavaScript link extraction (active source).

Fetches the root domain's HTML page, discovers all linked .js files,
downloads each script, and applies a subdomain regex — similar to
the LinkFinder technique used by BugBounty hunters.

Because this makes direct HTTP requests to the target, it lives in
sources/active/.
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from sources.base import BaseSource

_JS_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)

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

# Max JS files to download per domain (avoid unbounded crawls)
_MAX_JS_FILES = 30


class JsScrape(BaseSource):
    NAME = 'js_scrape'
    DESCRIPTION = 'Active: JS link extraction — discovers subdomains hardcoded in JS bundles'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        subdomain_re = re.compile(
            rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(domain)}',
            re.IGNORECASE,
        )

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers=_BROWSER_HEADERS,
        ) as client:
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
                        # Extract inline subdomains from the HTML itself
                        for m in subdomain_re.finditer(root_html):
                            subdomains.add(m.group(0).lower())
                        break
                except Exception:
                    continue

            if not root_html:
                return self._filter(subdomains, domain)

            # ── Step 2: collect JS URLs ───────────────────────────────
            js_urls: list[str] = []
            for src in _JS_SRC_RE.findall(root_html):
                js_url = urljoin(base_url, src)
                parsed = urlparse(js_url)
                # Only fetch JS on the same host or same root domain
                if domain in parsed.netloc:
                    js_urls.append(js_url)

            js_urls = list(dict.fromkeys(js_urls))[:_MAX_JS_FILES]
            if not js_urls:
                return self._filter(subdomains, domain)

            # ── Step 3: download JS and extract subdomains ────────────
            semaphore = asyncio.Semaphore(5)

            async def fetch_js(url: str) -> None:
                async with semaphore:
                    try:
                        js_resp = await asyncio.wait_for(
                            client.get(url, headers=_JS_HEADERS),
                            timeout=self.timeout,
                        )
                        if js_resp.status_code == 200:
                            for m in subdomain_re.finditer(js_resp.text):
                                subdomains.add(m.group(0).lower())
                    except Exception:
                        pass

            await asyncio.gather(*[fetch_js(u) for u in js_urls])

        return self._filter(subdomains, domain)
