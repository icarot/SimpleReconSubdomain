import base64
import re

import httpx

from core.config import get_key
from sources.base import BaseSource

_SCRAPE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
}


class Fofa(BaseSource):
    NAME = 'fofa'
    DESCRIPTION = 'FOFA - internet asset search engine (API key optional; scrapes fofa.so/result as fallback)'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('fofa_key')
        if api_key:
            return await self._fetch_api(domain, api_key)
        return await self._fetch_scrape(domain)

    # ------------------------------------------------------------------
    # Strategy 1: paid API (fofa_key required, needs API Query Balance)
    # ------------------------------------------------------------------
    async def _fetch_api(self, domain: str, api_key: str) -> set[str]:
        qbase64 = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        params = {
            'key': api_key,
            'qbase64': qbase64,
            'fields': 'domain,host',
            'size': 1000,
            'full': 'true',
        }
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await self._get(
                    client,
                    'https://fofa.so/api/v1/search/all',
                    params=params,
                )
                if resp.status_code == 401:
                    self._vlog(1, 'invalid API key')
                    return subdomains
                if resp.status_code != 200:
                    self._vlog(2, f'unexpected status {resp.status_code}')
                    return subdomains
                data = resp.json()
                if data.get('error'):
                    self._vlog(1, data.get('errmsg', 'API error'))
                    return subdomains
                for row in data.get('results', []):
                    for val in (row if isinstance(row, list) else [row]):
                        val = str(val).strip().lower()
                        for scheme in ('https://', 'http://'):
                            if val.startswith(scheme):
                                val = val[len(scheme):]
                        val = val.split('/')[0].split(':')[0]
                        if val:
                            subdomains.add(val)
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)

    # ------------------------------------------------------------------
    # Strategy 2: free scrape of fofa.so/result (no key needed)
    # ------------------------------------------------------------------
    async def _fetch_scrape(self, domain: str) -> set[str]:
        qbase64 = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        pattern = re.compile(
            rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(domain)}',
            re.IGNORECASE,
        )
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers=_SCRAPE_HEADERS,
            ) as client:
                resp = await self._get(
                    client,
                    'https://fofa.so/result',
                    params={'qbase64': qbase64},
                )
                if resp.status_code != 200:
                    self._vlog(2, f'scrape status {resp.status_code}')
                    return subdomains
                for m in pattern.finditer(resp.text):
                    subdomains.add(m.group(0).lower())
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
