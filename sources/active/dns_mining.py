import asyncio
import re
from sources.base import BaseSource


class DNSMining(BaseSource):
    NAME = 'dns_mining'

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._mine, domain)

    def _mine(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            import dns.resolver
            import dns.exception
        except ImportError:
            print('[!] dnspython not installed. Run: pip install dnspython')
            return subdomains

        # ── TXT / SPF records ────────────────────────────────────────
        try:
            for record in dns.resolver.resolve(domain, 'TXT'):
                text = str(record)
                for match in re.findall(r'include:([^\s"]+)', text):
                    subdomains.add(match)
                for match in re.findall(r'redirect=([^\s"]+)', text):
                    subdomains.add(match)
        except Exception:
            pass

        # ── MX records ───────────────────────────────────────────────
        try:
            for mx in dns.resolver.resolve(domain, 'MX'):
                host = str(mx.exchange).rstrip('.')
                if domain in host:
                    subdomains.add(host)
        except Exception:
            pass

        # ── DMARC record (reveals reporting addresses) ────────────────
        try:
            for record in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
                for email_domain in re.findall(r'mailto:[^@]+@([^\s;>]+)', str(record)):
                    if domain in email_domain:
                        subdomains.add(email_domain)
        except Exception:
            pass

        return self._filter(subdomains, domain)
