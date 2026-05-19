import asyncio
from sources.base import BaseSource


class ZoneTransfer(BaseSource):
    NAME = 'zone_transfer'

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._axfr, domain)

    def _axfr(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            import dns.exception
        except ImportError:
            print('[!] dnspython not installed. Run: pip install dnspython')
            return subdomains

        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
        except Exception:
            return subdomains

        for ns in ns_records:
            ns_str = str(ns.target).rstrip('.')
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_str, domain, timeout=10)
                )
                for name in zone.nodes.keys():
                    name_str = str(name)
                    if name_str != '@':
                        subdomains.add(f'{name_str}.{domain}')
                print(f'  [zone_transfer] AXFR SUCCESS on {ns_str}!')
            except Exception:
                pass  # AXFR denied - expected for most nameservers

        return self._filter(subdomains, domain)
