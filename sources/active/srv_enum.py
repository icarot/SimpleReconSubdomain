# -*- coding: utf-8 -*-
"""
SRV Record Enumeration (active source).

Queries common SRV record prefixes for the target domain to discover service
endpoints that often reveal subdomains not found via other techniques.

Examples of what SRV records expose:
  _autodiscover._tcp.example.com  → mail.example.com
  _sip._tcp.example.com           → pbx.example.com
  _ldap._tcp.example.com          → dc01.example.com

The list of probed SRV prefixes is loaded from config/srv_prefixes.json.

Detection level: Moderate — DNS queries to public resolvers (not target NS directly).
"""

import asyncio
import json
from pathlib import Path

import dns.resolver

from sources.base import BaseSource

_SRV_PREFIXES_FILE = Path(__file__).parent.parent.parent / 'config' / 'srv_prefixes.json'

# Fallback minimal list if config file is missing
_FALLBACK_PREFIXES = [
    '_http._tcp', '_https._tcp', '_ftp._tcp', '_ssh._tcp',
    '_smtp._tcp', '_imap._tcp', '_ldap._tcp', '_sip._tcp',
    '_autodiscover._tcp', '_kerberos._tcp',
]


def _load_prefixes() -> list[str]:
    try:
        with open(_SRV_PREFIXES_FILE, 'r') as fh:
            data = json.load(fh)
            if isinstance(data, list):
                return [str(p).strip() for p in data if p]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return _FALLBACK_PREFIXES


class Srv_enum(BaseSource):
    NAME = 'srv_enum'
    DESCRIPTION = 'Active: SRV record enumeration for common service prefixes'
    API_TOKEN_IS_REQUIREMENT = False

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._prefixes = _load_prefixes()

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._run, domain),
                timeout=max(self.timeout, 60),
            )
        except asyncio.TimeoutError:
            self._vlog(1, f'timed out after {self.timeout}s')
            return set()

    def _run(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = min(self.timeout, 5)
        resolver.lifetime = min(self.timeout, 10)

        for prefix in self._prefixes:
            srv_name = f'{prefix}.{domain}'
            try:
                answers = resolver.resolve(srv_name, 'SRV')
                for rdata in answers:
                    target = str(rdata.target).rstrip('.')
                    if target and target != '.':
                        subdomains.add(target.lower())
                        self._vlog(2, f'SRV {srv_name} → {target}:{rdata.port}')
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                pass
            except Exception as exc:
                self._log_exc(exc)

        return self._filter(subdomains, domain)
