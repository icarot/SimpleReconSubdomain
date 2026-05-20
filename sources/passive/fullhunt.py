import httpx
from sources.base import BaseSource
from core.config import get_key


class FullHunt(BaseSource):
    """
    Queries the FullHunt API for subdomains of the target domain.

    FullHunt continuously discovers and indexes internet-exposed hosts,
    including cloud-hosted assets (AWS, Azure, GCP).  The /subdomains
    endpoint returns the full hostname list associated with a domain.

    Authentication is required (fullhunt_token).  A free-tier account
    can be registered at https://fullhunt.io to obtain a key.
    """

    NAME = 'fullhunt'
    REQUIRES_API_KEY = True

    async def fetch(self, domain: str) -> set[str]:
        token = get_key('fullhunt_token')
        if not token:
            return set()

        url = f'https://fullhunt.io/api/v1/domain/{domain}/details'
        headers: dict = {'X-API-Key': token}
        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, headers=headers
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains

                data = resp.json()
                # 'hosts' is a list of host objects; extract the 'host' field from each
                for entry in data.get('hosts', []):
                    if isinstance(entry, dict):
                        host = entry.get('host', '').strip().lower()
                    elif isinstance(entry, str):
                        host = entry.strip().lower()
                    else:
                        continue
                    if host:
                        subdomains.add(host)

        except Exception:
            pass

        return self._filter(subdomains, domain)
