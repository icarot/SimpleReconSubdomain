"""
ASN → CIDR → PTR sweep (active source).

ptr_sweep.py covers only the /24 block surrounding the target's IP.  This
module maps the target's full IP space by:

  1. Resolving the target domain to one or more IPs.
  2. Looking up each IP on bgp.he.net to find the owning ASN and org name.
  3. Filtering out cloud/CDN ASNs (AWS, Google, Azure, Cloudflare, …) —
     those would sweep millions of unrelated IPs.
  4. Fetching the ASN's prefix list from bgp.he.net.
  5. Performing async PTR (reverse DNS) lookups across all IPs in every
     prefix ≤ /_MAX_PREFIX_SIZE, collecting hostnames that belong to the
     target domain.

Because this makes direct HTTP + DNS requests it lives in sources/active/.
No API key required.
"""
import asyncio
import ipaddress
import re
import socket

from bs4 import BeautifulSoup

from sources.base import BaseSource

_BGP_IP_URL  = 'https://bgp.he.net/ip/{ip}'
_BGP_ASN_URL = 'https://bgp.he.net/AS{asn}'

_MAX_PREFIXES    = 5    # maximum number of CIDR blocks to sweep
_MAX_PREFIX_SIZE = 20   # ignore blocks larger than /20 (>4096 IPs)
_PTR_CONCURRENCY = 100

# Cloud/CDN ASN org keywords — skip these entirely
_CLOUD_ORGS = (
    'amazon', 'aws', 'google', 'microsoft', 'azure', 'cloudflare',
    'fastly', 'akamai', 'limelight', 'level3', 'cogent',
)

_RE_ASN = re.compile(r'AS(\d+)', re.IGNORECASE)

_BROWSER_UA = (
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
)


class Asn_sweep(BaseSource):
    NAME = 'asn_sweep'
    DESCRIPTION = 'Active: BGP ASN lookup (bgp.he.net) → CIDR prefixes → PTR sweep'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                self._run_async(domain, loop),
                timeout=max(self.timeout, 120),
            )
        except asyncio.TimeoutError:
            self._vlog(1, 'timed out')
            return set()

    async def _run_async(
        self, domain: str, loop: asyncio.AbstractEventLoop
    ) -> set[str]:
        # ── Step 1: Resolve domain → IPs ─────────────────────────────
        try:
            _, _, ips = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname_ex, domain),
                timeout=10,
            )
        except Exception:
            return set()

        if not ips:
            return set()

        subdomains: set[str] = set()

        headers = {
            'User-Agent': _BROWSER_UA,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }

        async with self._make_client(headers=headers) as client:
            for ip in ips[:3]:
                prefixes = await self._get_own_prefixes(client, ip, domain)
                if prefixes:
                    found = await self._ptr_sweep(prefixes, domain, loop)
                    subdomains |= found
                    break  # one successful ASN lookup is enough

        return self._filter(subdomains, domain)

    async def _get_own_prefixes(
        self, client, ip: str, domain: str
    ) -> list[str]:
        """Return IPv4 CIDR prefixes owned by the target's ASN.

        Returns [] when the ASN belongs to a cloud/CDN provider.
        """
        # ── Step 2: IP → ASN via bgp.he.net ──────────────────────────
        try:
            resp = await asyncio.wait_for(
                client.get(_BGP_IP_URL.format(ip=ip)),
                timeout=15,
            )
        except Exception:
            return []

        if resp.status_code != 200:
            return []

        soup = BeautifulSoup(resp.text, 'html.parser')

        # Find ASN links on the page: href="/AS12345"
        asn_number: int | None = None
        asn_org: str = ''
        for a in soup.find_all('a', href=True):
            href = a['href']
            m = re.match(r'^/AS(\d+)$', href)
            if m:
                asn_number = int(m.group(1))
                asn_org = a.get_text(strip=True).lower()
                break

        if not asn_number:
            self._vlog(2, f'{ip}: ASN not found on bgp.he.net')
            return []

        # ── Step 3: Filter cloud ASNs ─────────────────────────────────
        if any(kw in asn_org for kw in _CLOUD_ORGS):
            self._vlog(2, f'{ip} → AS{asn_number} ({asn_org}) is a cloud provider — skipping')
            return []

        self._vlog(1, f'{ip} → AS{asn_number} ({asn_org})')

        # ── Step 4: ASN → prefix list via bgp.he.net ──────────────────
        try:
            resp2 = await asyncio.wait_for(
                client.get(_BGP_ASN_URL.format(asn=asn_number)),
                timeout=15,
            )
        except Exception:
            return []

        if resp2.status_code != 200:
            return []

        soup2 = BeautifulSoup(resp2.text, 'html.parser')
        prefixes: list[str] = []

        # bgp.he.net lists prefixes as links: href="/net/1.2.3.0/24"
        for a in soup2.find_all('a', href=True):
            href = a['href']
            m = re.match(r'^/net/([\d.]+/\d+)$', href)
            if not m:
                continue
            prefix = m.group(1)
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                # Only IPv4, only small-enough blocks
                if isinstance(net, ipaddress.IPv4Network) and net.prefixlen >= _MAX_PREFIX_SIZE:
                    prefixes.append(prefix)
            except ValueError:
                continue
            if len(prefixes) >= _MAX_PREFIXES:
                break

        self._vlog(1, f'AS{asn_number}: {len(prefixes)} prefix(es) to sweep')
        return prefixes

    async def _ptr_sweep(
        self,
        prefixes: list[str],
        domain: str,
        loop: asyncio.AbstractEventLoop,
    ) -> set[str]:
        """PTR sweep across all IPs in every prefix."""
        subdomains: set[str] = set()
        sem = asyncio.Semaphore(_PTR_CONCURRENCY)

        async def lookup(ip_str: str) -> None:
            async with sem:
                try:
                    hostname, *_ = await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyaddr, ip_str),
                        timeout=3,
                    )
                    h = hostname.rstrip('.').lower()
                    if h == domain or h.endswith(f'.{domain}'):
                        subdomains.add(h)
                except Exception:
                    pass

        tasks = [
            lookup(str(host))
            for prefix in prefixes
            for host in ipaddress.ip_network(prefix, strict=False).hosts()
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        self._vlog(1, f'PTR sweep complete: {len(subdomains)} hostname(s) found')
        return subdomains
