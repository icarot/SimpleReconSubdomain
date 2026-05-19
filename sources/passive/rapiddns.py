import re
import httpx
from sources.base import BaseSource


class RapidDNS(BaseSource):
    NAME = 'rapiddns'

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://rapiddns.io/subdomain/{domain}?full=1#result'
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains
                pattern = re.compile(
                    r'<td>\s*([\w.\-]+\.' + re.escape(domain) + r')\s*</td>',
                    re.IGNORECASE,
                )
                subdomains.update(pattern.findall(resp.text))
        except Exception:
            pass
        return self._filter(subdomains, domain)
