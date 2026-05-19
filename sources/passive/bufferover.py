import httpx
from sources.base import BaseSource


class BufferOver(BaseSource):
    NAME = 'bufferover'

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://tls.bufferover.run/dns?q=.{domain}'
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains
                data = resp.json()
                all_records = data.get('FDNS_A', []) + data.get('RDNS', [])
                for record in all_records:
                    # Format: "IP,hostname" or "hostname,IP"
                    parts = record.split(',')
                    for part in parts:
                        part = part.strip()
                        if part and not part.replace('.', '').isdigit():
                            subdomains.add(part)
        except Exception:
            pass
        return self._filter(subdomains, domain)
