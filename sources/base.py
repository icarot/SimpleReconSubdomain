import asyncio
import ipaddress
from abc import ABC, abstractmethod

import httpx

import core.colors as colors

_DEFAULT_UA = 'SimpleReconSubdomain/2'


class BaseSource(ABC):
    NAME: str = ''
    DESCRIPTION: str = ''
    API_TOKEN_IS_REQUIREMENT: bool = False

    def __init__(
        self,
        timeout: int = 30,
        rate_limit: int = 0,
        verbose: int = 0,
        proxy: str | None = None,
        user_agent: str = _DEFAULT_UA,
    ) -> None:
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.proxy = proxy
        self.user_agent = user_agent
        # Semaphore to cap concurrent requests per source (0 = unlimited)
        self._sem: asyncio.Semaphore | None = (
            asyncio.Semaphore(rate_limit) if rate_limit > 0 else None
        )
        # Out-of-scope elements found during fetch(); populated by _filter()
        # and by active sources that collect URLs/IPs.
        self.extras: dict[str, set] = {
            'hosts': set(),
            'ips':   set(),
            'urls':  set(),
        }

    def _make_client(self, **kwargs) -> httpx.AsyncClient:
        """
        Return a pre-configured AsyncClient with proxy and User-Agent applied.

        Callers can override any default by passing kwargs; 'headers' are
        merged (caller values win) rather than replaced.
        """
        merged_headers: dict = {'User-Agent': self.user_agent}
        if 'headers' in kwargs:
            merged_headers.update(kwargs.pop('headers'))
        client_kwargs: dict = {
            'timeout': self.timeout,
            'follow_redirects': True,
            'headers': merged_headers,
        }
        if self.proxy:
            client_kwargs['proxy'] = self.proxy
        client_kwargs.update(kwargs)
        return httpx.AsyncClient(**client_kwargs)

    def _vlog(self, level: int, msg: str) -> None:
        """Print *msg* when self.verbose >= *level*."""
        if self.verbose >= level:
            print(colors.format_msg(f'[*] [{self.NAME}] {msg}'))

    def _log_exc(self, e: Exception) -> None:
        """Print exception class and message at verbose level 4+."""
        if self.verbose >= 4:
            print(colors.format_msg(f'[!] [{self.NAME}] {type(e).__name__}: {e}'))

    async def _get(self, client, url: str, **kwargs):
        """Wrap client.get(); enforces rate_limit, logs HTTP status and body preview."""
        if self._sem:
            async with self._sem:
                return await self._do_get(client, url, **kwargs)
        return await self._do_get(client, url, **kwargs)

    async def _do_get(self, client, url: str, **kwargs):
        resp = await client.get(url, **kwargs)
        if self.verbose >= 2:
            self._vlog(2, f'HTTP {resp.status_code}')
        if self.verbose >= 3:
            preview = resp.text[:400].replace('\n', ' ')
            self._vlog(3, preview)
        return resp

    @abstractmethod
    async def fetch(self, domain: str) -> set[str]:
        """Fetch subdomains for *domain*. Must always return a set (never raises)."""

    def _filter(self, subdomains: set, domain: str) -> set[str]:
        """Keep only entries that are (sub)domains of *domain*.

        Discarded items that look like valid hostnames or IPs are saved
        in self.extras so callers can optionally surface them.
        """
        result: set[str] = set()
        for sub in subdomains:
            if not sub:
                continue
            sub = sub.strip().lower().lstrip('*.')
            if not sub:
                continue
            if sub == domain or sub.endswith(f'.{domain}'):
                result.add(sub)
            else:
                try:
                    ipaddress.ip_address(sub)
                    self.extras['ips'].add(sub)
                except ValueError:
                    if '.' in sub and not sub.startswith('.') and len(sub) <= 253:
                        self.extras['hosts'].add(sub)
        return result
