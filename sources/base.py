from abc import ABC, abstractmethod


class BaseSource(ABC):
    NAME: str = ''
    DESCRIPTION: str = ''
    API_TOKEN_IS_REQUIREMENT: bool = False

    def __init__(self, timeout: int = 30, rate_limit: int = 0, verbose: int = 0) -> None:
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verbose = verbose

    def _vlog(self, level: int, msg: str) -> None:
        """Print *msg* when self.verbose >= *level*."""
        if self.verbose >= level:
            print(f'\033[94m[*]\033[0m \033[96m[{self.NAME}]\033[0m {msg}')

    def _log_exc(self, e: Exception) -> None:
        """Print exception class and message at verbose level 4+."""
        if self.verbose >= 4:
            print(f'\033[91m[!] [{self.NAME}] {type(e).__name__}: {e}\033[0m')

    async def _get(self, client, url: str, **kwargs):
        """Wrap client.get(); logs HTTP status (level 2) and body preview (level 3)."""
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
        """Keep only entries that are (sub)domains of *domain*."""
        result: set[str] = set()
        for sub in subdomains:
            if not sub:
                continue
            sub = sub.strip().lower().lstrip('*.')
            if sub and (sub == domain or sub.endswith(f'.{domain}')):
                result.add(sub)
        return result
