"""
PTR sweep — reverse-DNS enumeration on /24 of target IP space.

Resolves the target domain to its A records, then for each unique /24 CIDR
block performs PTR (reverse DNS) lookups on every host IP. PTR records that
resolve to a hostname within the target domain are returned as subdomains.

This is inspired by Amass/dnsx reverse-sweep. Useful for discovering internal
naming schemas and subdomains not listed in any DNS zone directly.

No API key required; uses system DNS (or the OS resolver).
"""
import asyncio
import ipaddress
import socket

from sources.base import BaseSource

# Max /24 blocks to sweep per target (limits scan time on very large ASNs)
_MAX_CIDRS = 3
# Concurrency for PTR lookups (per /24 block that's 256 IPs)
_CONCURRENCY = 50


class PtrSweep(BaseSource):
    NAME = 'ptr_sweep'
    DESCRIPTION = 'Active: reverse-DNS PTR sweep on /24 blocks of target IPs'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                self._run_async(domain, loop),
                timeout=max(self.timeout, 90),
            )
        except asyncio.TimeoutError:
            self._vlog(1, 'PTR sweep timed out')
            return set()

    async def _run_async(self, domain: str, loop: asyncio.AbstractEventLoop) -> set[str]:
        # Resolve the target to IPs
        try:
            _, _, ips = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname_ex, domain),
                timeout=10,
            )
        except Exception:
            return set()

        if not ips:
            return set()

        # Collect unique /24 networks
        cidrs: list[ipaddress.IPv4Network] = []
        seen_cidrs: set[str] = set()
        for ip_str in ips:
            try:
                net = ipaddress.ip_network(f'{ip_str}/24', strict=False)
                key = str(net)
                if key not in seen_cidrs and len(cidrs) < _MAX_CIDRS:
                    seen_cidrs.add(key)
                    cidrs.append(net)
            except ValueError:
                continue

        if not cidrs:
            return set()

        self._vlog(1, f'sweeping {len(cidrs)} /24 block(s): {", ".join(str(c) for c in cidrs)}')

        subdomains: set[str] = set()
        sem = asyncio.Semaphore(_CONCURRENCY)

        async def ptr_lookup(ip_str: str) -> None:
            async with sem:
                try:
                    hostname, *_ = await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyaddr, ip_str),
                        timeout=3,
                    )
                    hostname = hostname.rstrip('.').lower()
                    if hostname == domain or hostname.endswith(f'.{domain}'):
                        subdomains.add(hostname)
                except Exception:
                    pass

        tasks = [
            ptr_lookup(str(host))
            for net in cidrs
            for host in net.hosts()
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._filter(subdomains, domain)
