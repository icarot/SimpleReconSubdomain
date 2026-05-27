"""
Wildcard DNS detection.

Inspired by PureDNS's multi-probe approach: instead of a single random-subdomain
probe (which gives a false negative under DNS load-balancing or round-robin setups),
we fire N probes and confirm a wildcard only when the majority resolve.

The union of all wildcard IPs is returned for use during brute-force filtering.
"""

import random
import string

import aiodns

import core.colors as colors


async def detect_wildcard(
    domain: str,
    resolver: aiodns.DNSResolver,
    tests: int = 3,
    verbose: int = 0,
) -> tuple[bool, set[str]]:
    """
    Test whether *domain* has wildcard DNS configured (*.domain → resolves).

    Args:
        domain:   Target domain.
        resolver: Shared aiodns.DNSResolver instance.
        tests:    Number of random probes to fire (default 3, configurable via
                  --wildcard-tests). Wildcard is confirmed when ≥ ceil(tests/2)
                  probes resolve successfully.
        verbose:  Verbosity level.

    Returns:
        (is_wildcard, wildcard_ips) — wildcard_ips is the *union* of all IPs
        returned across all successful probes; used to filter false positives
        during brute-force.
    """
    wildcard_ips: set[str] = set()
    resolved_count = 0
    threshold = max(1, (tests + 1) // 2)  # ceil(tests / 2)

    probes = [
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=16)) + f'.{domain}'
        for _ in range(tests)
    ]

    for probe in probes:
        if verbose >= 2:
            print(colors.format_msg(f'[*] [wildcard] probe → {probe}'))
        try:
            result = await resolver.query(probe, 'A')
            resolved_count += 1
            for r in result:
                wildcard_ips.add(r.host)
            if verbose >= 2:
                ips = ', '.join(r.host for r in result)
                print(colors.format_msg(f'[*] [wildcard] resolved → {ips}'))
        except aiodns.error.DNSError as exc:
            if verbose >= 4:
                print(colors.format_msg(f'[-] [wildcard] probe failed: {exc!r}'))

    is_wildcard = resolved_count >= threshold
    if verbose >= 1 and is_wildcard:
        print(colors.format_msg(
            f'[!] [wildcard] {resolved_count}/{tests} probes resolved '
            f'(threshold {threshold}) → wildcard confirmed, IPs: {wildcard_ips}'
        ))
    return is_wildcard, wildcard_ips
