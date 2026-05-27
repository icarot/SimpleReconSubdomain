# -*- coding: utf-8 -*-
"""
DNS Resolver Health Check.

Inspired by PureDNS's resolver verification step: before running a large-scale
brute-force, probe every resolver in the list against a known-stable domain
(example.com / IANA) and discard the ones that don't respond.

This eliminates:
  - Dead / unreachable resolver IPs
  - Resolvers that return garbage (DNS hijacking / spoofing)
  - Rate-limited resolvers that would silently drop queries

Usage:
    from bruteforce.resolver_check import check_resolvers
    working = await check_resolvers(resolver_list, verbose=1)
"""

import asyncio

import aiodns

import core.colors as colors

# Use a well-known domain that should always resolve to 93.184.216.34 (IANA)
_TEST_DOMAIN = 'example.com'
_TEST_EXPECTED_PREFIX = '93.184.'   # expected answer prefix; loose check
_CHECK_TIMEOUT = 3                  # seconds per resolver
_CHECK_CONCURRENCY = 100            # concurrent probes


async def check_resolvers(
    resolvers: list[str],
    timeout: int = _CHECK_TIMEOUT,
    concurrency: int = _CHECK_CONCURRENCY,
    verbose: int = 0,
    quiet: bool = False,
) -> list[str]:
    """
    Test each resolver IP by querying *_TEST_DOMAIN* and keep only the ones
    that return a valid A record response.

    Args:
        resolvers:   List of resolver IP addresses to test.
        timeout:     Per-resolver DNS query timeout in seconds.
        concurrency: Max concurrent health-check queries.
        verbose:     Verbosity level (1+ prints individual results).
        quiet:       Suppress all output when True.

    Returns:
        Ordered list of responsive resolver IPs (same order as input).
    """
    if not resolvers:
        return []

    semaphore = asyncio.Semaphore(concurrency)
    passed: list[bool] = [False] * len(resolvers)

    if not quiet:
        print(colors.format_msg(
            f'[*] [check-resolvers] Testing {len(resolvers)} resolvers '
            f'against {_TEST_DOMAIN}…'
        ))

    async def _test(idx: int, ip: str) -> None:
        async with semaphore:
            r = aiodns.DNSResolver(nameservers=[ip], timeout=timeout)
            try:
                result = await r.query(_TEST_DOMAIN, 'A')
                if result and any(
                    rr.host.startswith(_TEST_EXPECTED_PREFIX) for rr in result
                ):
                    passed[idx] = True
                    if verbose >= 2 and not quiet:
                        ips = ', '.join(rr.host for rr in result)
                        print(colors.format_msg(f'[+] [check-resolvers] {ip} → {ips}'))
            except Exception as exc:
                if verbose >= 3 and not quiet:
                    print(colors.format_msg(
                        f'[-] [check-resolvers] {ip} failed: {exc!r}'
                    ))

    await asyncio.gather(*[_test(i, ip) for i, ip in enumerate(resolvers)])

    working = [ip for ip, ok in zip(resolvers, passed) if ok]
    removed = len(resolvers) - len(working)

    if not quiet:
        status = colors.format_msg(
            f'[*] [check-resolvers] {len(working)}/{len(resolvers)} resolvers active'
            + (f' ({removed} removed)' if removed else '')
        )
        print(status)

    if verbose >= 1 and not quiet and working:
        print(colors.format_msg(
            f'[*] [check-resolvers] Using {len(working)} verified resolvers'
        ))

    return working
