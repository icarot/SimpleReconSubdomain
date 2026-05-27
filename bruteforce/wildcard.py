import random
import string

import aiodns

import core.colors as colors


async def detect_wildcard(
    domain: str, resolver: aiodns.DNSResolver, verbose: int = 0
) -> tuple[bool, set[str]]:
    """
    Test whether *domain* has wildcard DNS configured (*.domain → resolves).

    Returns:
        (is_wildcard, wildcard_ips) - wildcard_ips is the set of IPs returned
        by the random probe, used later to filter brute-force false positives.
    """
    wildcard_ips: set[str] = set()
    probe = ''.join(random.choices(string.ascii_lowercase, k=16)) + f'.{domain}'
    if verbose >= 2:
        print(colors.format_msg(f'[*] [wildcard] probe → {probe}'))
    try:
        result = await resolver.query(probe, 'A')
        for r in result:
            wildcard_ips.add(r.host)
        return True, wildcard_ips
    except aiodns.error.DNSError as exc:
        if verbose >= 4:
            print(colors.format_msg(f'[-] [wildcard] probe failed: {exc!r}'))
        return False, wildcard_ips
