"""
Bing search — zero-auth subdomain discovery via search engine.

Queries Bing using multiple URL templates with different form/shajax parameters
to maximise result coverage and reduce bot-detection blocking.

Extraction strategy (no external parser required):
  1. hover-url="..." attributes — the most reliable Bing result URL signal
  2. <cite> tag text — Bing places the breadcrumb URL inside <cite> tags
  3. <a href=...> anchors filtered to external (non-Bing) destinations

A random delay is applied between requests to mimic human browsing.
UA is rotated per request from a small desktop-browser pool.

Inspired by BingDorker in string-x (github.com/MrCl0wnLab/string-x).
No API key required.
"""
import asyncio
import random
import re
from urllib.parse import quote_plus, urlparse

from sources.base import BaseSource

# ── Bing’s own infrastructure — never useful as subdomain results ─────────────
_BLOCKLIST = frozenset([
    'bing.com', 'microsoft.com', 'msn.com', 'live.com',
    'microsoftonline.com', 'windows.com', 'office.com',
    'outlook.com', 'hotmail.com',
])

# ── Desktop browser UA pool — rotated per request ──────────────────────
_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
]

# ── Multiple URL templates (from string-x BingDorker) ────────────────────
# Different form= and shajax= values bypass some bot-detection rules
_URL_TEMPLATES = [
    'https://www.bing.com/search?q={QUERY}&form=DEEPSH&shm=cr&shajax=2',
    'https://www.bing.com/search?q={QUERY}&shm=cr&form=DEEPSH&shajax=1',
    'https://www.bing.com/search?q={QUERY}&filt=rf&first=1&FORM=PERE',
    'https://www.bing.com/search?q={QUERY}&filt=rf&first=11&FORM=PERE',
    'https://www.bing.com/search?q={QUERY}&filt=rf&first=21&FORM=PERE',
    'https://www.bing.com/search?q={QUERY}&filt=rf&first=31&FORM=PERE',
    'https://www.bing.com/search?q={QUERY}&filt=rf&first=41&FORM=PERE',
    'https://www.bing.com/search?q={QUERY}&filt=rf&first=51&FORM=PERE',
]

# ── Extraction regexes ──────────────────────────────────────────
_RE_HOVER = re.compile(r'hover-url="(https?://[^"]+)"', re.IGNORECASE)
_RE_CITE  = re.compile(r'<cite[^>]*>(.*?)</cite>', re.IGNORECASE | re.DOTALL)
_RE_HREF  = re.compile(r'<a[^>]+href="(https?://(?!(?:www\.)?bing\.com)[^"]+)"', re.IGNORECASE)
_RE_TAGS  = re.compile(r'<[^>]+')


def _extract_urls(html: str) -> set[str]:
    """Pull candidate URLs from a Bing result page without BeautifulSoup."""
    urls: set[str] = set()

    # 1. hover-url="..." — most reliable signal
    for m in _RE_HOVER.finditer(html):
        urls.add(m.group(1))

    # 2. <cite> breadcrumbs — strip tags, normalise Bing’s path separator
    for m in _RE_CITE.finditer(html):
        text = _RE_TAGS.sub('', m.group(1)).strip()
        text = text.replace(' \u203a ', '/').replace('...', '').replace('\u2026', '')
        if not text.startswith(('http://', 'https://')):
            text = 'https://' + text
        urls.add(text)

    # 3. <a href> anchors pointing outside bing.com
    for m in _RE_HREF.finditer(html):
        urls.add(m.group(1))

    return urls


def _to_hostname(url: str) -> str | None:
    """Return bare hostname (no www.) from a URL, or None on error."""
   
    try:
        url = url.replace('>', '')  # unescape & in URLs
        h = urlparse(url).hostname or ''
        return h.lower().lstrip('www.') or None
    except Exception:
        return None


class Bing(BaseSource):
    NAME = 'bing'
    DESCRIPTION = 'Bing search - zero-auth subdomain discovery (multi-template, anti-bot)'
    API_TOKEN_IS_REQUIREMENT = False

    # Random inter-request delay (seconds) — mimics human browsing pace
    _DELAY_MIN = 1.5
    _DELAY_MAX = 3.5

    async def fetch(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        encoded = quote_plus(f'{domain}')

        async with self._make_client() as client:
            for idx, template in enumerate(_URL_TEMPLATES, 1):
                url = template.replace('{QUERY}', encoded)
                ua  = random.choice(_USER_AGENTS)

                try:
                    resp = await self._get(client, url, headers={
                        'User-Agent':      ua,
                        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Referer':         'https://www.bing.com/',
                        'DNT':             '1',
                    })
                    
                except Exception as e:
                    self._log_exc(e)
                    continue

                if resp.status_code == 403:
                    self._vlog(1, 'bot-detection 403 — stopping')
                    break
                if resp.status_code != 200:
                    self._vlog(2, f'HTTP {resp.status_code} — skipping template {idx}')
                    continue

                before = len(subdomains)
                for raw_url in _extract_urls(resp.text):
                    host = _to_hostname(raw_url)
                    if not host:
                        continue
                    if any(bl in host for bl in _BLOCKLIST):
                        continue
                    if host == domain or host.endswith(f'.{domain}'):
                        subdomains.add(host)

                self._vlog(1, f'+{len(subdomains) - before} subdomains (template {idx}/{len(_URL_TEMPLATES)})')

                await asyncio.sleep(random.uniform(self._DELAY_MIN, self._DELAY_MAX))

        return self._filter(subdomains, domain)
