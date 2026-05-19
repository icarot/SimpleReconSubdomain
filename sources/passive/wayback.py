import httpx
from sources.base import BaseSource


class Wayback(BaseSource):
    NAME = 'wayback'

    async def fetch(self, domain: str) -> set[str]:
        url = (
            f'http://web.archive.org/cdx/search/cdx'
            f'?url=*.{domain}&output=text&fl=original&collapse=urlkey'
        )
        #http://web.archive.org/cdx/search/cdx?url=*.testando&output=text&fl=original&collapse=urlkey
     
        subdomains: set[str] = set()
        self.timeout = 50.0  # Wayback can be slow to respond, increase timeout
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return subdomains
                for line in resp.text.splitlines():
                    line = line.strip()
                    if '://' in line:
                        # Extract host: strip scheme, path, port
                        host = line.split('://')[1].split('/')[0].split(':')[0]
                        subdomains.add(host)
        except Exception as e:
            print(f'[!] Error fetching Wayback data for {domain}: {e}')
        return self._filter(subdomains, domain)
