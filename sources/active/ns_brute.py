"""
Secondary NS discovery + multi-vector zone transfer (active source).

zone_transfer.py only tries AXFR on the publicly listed NS records — the ones
most likely to have strict ACLs.  This module goes further:

  1. Collects NS candidates from multiple sources:
       - Public NS records (same as zone_transfer)
       - SOA MNAME field  (primary NS, often differs from public NS)
       - Brute-force of common NS naming patterns (ns1-ns5, dns1-dns3, ...)
  2. Compares SOA serials across NSes — a lagging secondary may have an
     outdated ACL that still permits zone transfer.
  3. Attempts AXFR then IXFR (serial=0) on every candidate.

Because this makes direct DNS queries to nameservers it lives in sources/active/.
No API key required; uses dnspython (already a dependency).
"""
import asyncio
import socket

from sources.base import BaseSource

# Common nameserver hostname prefixes to brute-force
_NS_PREFIXES = [
    'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5',
    'dns', 'dns1', 'dns2', 'dns3',
    'nameserver', 'nameserver1', 'nameserver2',
    'resolver', 'auth', 'hidden',
    'primary', 'secondary', 'slave',
]

_AXFR_TIMEOUT = 15  # per-transfer timeout (seconds)
_DNS_TIMEOUT  = 5


class Ns_brute(BaseSource):
    NAME = 'ns_brute'
    DESCRIPTION = 'Active: secondary NS discovery + AXFR/IXFR multi-vector zone transfer'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._run, domain),
                timeout=max(self.timeout, 90),
            )
        except asyncio.TimeoutError:
            self._vlog(1, 'timed out')
            return set()

    def _run(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            import dns.rdatatype
            import dns.exception
        except ImportError:
            return subdomains

        resolver = dns.resolver.Resolver()
        resolver.timeout  = _DNS_TIMEOUT
        resolver.lifetime = _DNS_TIMEOUT

        # ── Step 1: Collect NS candidates ────────────────────────────
        candidates: list[tuple[str, str]] = []  # [(ip, hostname)]
        seen_ips: set[str] = set()

        def _resolve_add(hostname: str) -> None:
            hostname = hostname.rstrip('.')
            try:
                for rdata in resolver.resolve(hostname, 'A'):
                    ip = str(rdata.address)
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        candidates.append((ip, hostname))
            except Exception:
                pass

        # Public NS records
        try:
            for rdata in resolver.resolve(domain, 'NS'):
                _resolve_add(str(rdata.target))
        except Exception:
            pass

        # SOA MNAME — the real primary NS, often not in the NS record set
        try:
            soa = resolver.resolve(domain, 'SOA')
            mname = str(soa[0].mname).rstrip('.')
            _resolve_add(mname)
        except Exception:
            pass

        # Brute-force common NS names
        for prefix in _NS_PREFIXES:
            _resolve_add(f'{prefix}.{domain}')

        if not candidates:
            self._vlog(1, 'no NS candidates resolved')
            return subdomains

        self._vlog(1, f'{len(candidates)} NS candidate(s): {[h for _, h in candidates]}')

        # ── Step 2: Detect SOA serial drift ──────────────────────────
        serials: dict[str, int] = {}
        for ip, hostname in candidates:
            try:
                soa_ans = resolver.resolve_at(ip, domain, 'SOA')
                serials[hostname] = soa_ans[0].serial
            except Exception:
                pass

        if len(set(serials.values())) > 1:
            self._vlog(1, f'SOA serial drift detected: {serials} — lagging NS may allow AXFR')

        # ── Step 3: Try AXFR then IXFR on every candidate ────────────
        for ip, hostname in candidates:
            for rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR):
                try:
                    xfr = dns.query.xfr(
                        ip, domain,
                        rdtype=rdtype,
                        timeout=_AXFR_TIMEOUT,
                        serial=0,           # forces full transfer even with IXFR
                        lifetime=_AXFR_TIMEOUT,
                    )
                    zone = dns.zone.from_xfr(xfr)
                    for name in zone.nodes.keys():
                        name_str = str(name)
                        if name_str != '@':
                            subdomains.add(f'{name_str}.{domain}')
                    rdtype_name = 'AXFR' if rdtype == dns.rdatatype.AXFR else 'IXFR'
                    self._vlog(1, f'{rdtype_name} SUCCESS on {hostname} ({ip}) — {len(zone.nodes)} records')
                    break  # no need to try IXFR if AXFR succeeded
                except Exception:
                    pass

        return self._filter(subdomains, domain)
