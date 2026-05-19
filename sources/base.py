from abc import ABC, abstractmethod


class BaseSource(ABC):
    NAME: str = ''
    REQUIRES_API_KEY: bool = False

    def __init__(self, timeout: int = 30, rate_limit: int = 0) -> None:
        self.timeout = timeout
        self.rate_limit = rate_limit

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
