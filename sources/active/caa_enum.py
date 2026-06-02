"""
CAA record mining (active source).

Queries DNS CAA records (RFC 8659) for the target domain.  The `iodef` tag
is designed for abuse reporting and frequently contains full URLs or mailto
addresses that leak internal hostnames not published anywhere else.

  target.com CAA 0 iodef "https://jira.internal.target.com/CAA"  ← hostname leak
  target.com CAA 0 iodef "mailto:security@corp.target.com"       ← hostname leak
  target.com CAA 0 issuewild "letsencrypt.org"                   ← wildcard confirmed

Because this makes direct DNS queries to authoritative nameservers it lives in
sources/active/.  No API key required; uses dnspython (already a dependency).
"""
import asyncio
import re

from sources.base import BaseSource

_RE_HTTPS_HOST = re.compile(r'https?://([^/\s"\']+)', re.IGNORECASE)
_RE_MAILTO     = re.compile(r'mailto:[^@]+@([^\s;>"\']+)', re.IGNORECASE)


class Caa_enum(BaseSource):
    NAME = 'caa_enum'
    DESCRIPTION = 'Active: CAA record iodef leak mining (RFC 8659)'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._mine, domain),
                timeout=max(self.timeout, 20),
            )
        except asyncio.TimeoutError:
            self._vlog(1, 'timed out')
            return set()

    def _mine(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            import dns.resolver
            import dns.exception
        except ImportError:
            return subdomains

        # Query CAA on the root domain and common subdomains worth checking
        targets = [domain]

        for target in targets:
            try:
                answers = dns.resolver.resolve(target, 'CAA')
            except Exception:
                continue

            for rdata in answers:
                try:
                    tag   = rdata.tag.decode('utf-8', errors='ignore').lower()
                    value = rdata.value.decode('utf-8', errors='ignore').strip('"').strip()
                except Exception:
                    continue

                if tag == 'iodef':
                    # Extract hostnames from https:// URLs in iodef value
                    for m in _RE_HTTPS_HOST.finditer(value):
                        subdomains.add(m.group(1).rstrip('/'))

                    # Extract hostnames from mailto: addresses
                    for m in _RE_MAILTO.finditer(value):
                        subdomains.add(m.group(1))

                elif tag == 'issuewild' and value and value != ';':
                    # issuewild present → wildcard cert authorised → log as signal
                    self._vlog(1, f'issuewild detected on {target}: {value}')

        return self._filter(subdomains, domain)
