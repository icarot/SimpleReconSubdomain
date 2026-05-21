import httpx
from sources.base import BaseSource


class BufferOver(BaseSource):
    NAME = 'bufferover'
    DESCRIPTION = 'BufferOver - Rapid7 FDNS via TLS'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        url = f'https://tls.bufferover.run/dns?q=.{domain}'
        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await self._get(client, url)
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
        except Exception as e:
            self._log_exc(e)
        return self._filter(subdomains, domain)
