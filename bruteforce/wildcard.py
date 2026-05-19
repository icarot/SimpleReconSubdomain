import random
import string

import aiodns


async def detect_wildcard(
    domain: str, resolver: aiodns.DNSResolver
) -> tuple[bool, set[str]]:
    """
    Test whether *domain* has wildcard DNS configured (*.domain → resolves).

    Returns:
        (is_wildcard, wildcard_ips) - wildcard_ips is the set of IPs returned
        by the random probe, used later to filter brute-force false positives.
    """
    wildcard_ips: set[str] = set()
    probe = ''.join(random.choices(string.ascii_lowercase, k=16)) + f'.{domain}'
    try:
        result = await resolver.query(probe, 'A')
        for r in result:
            wildcard_ips.add(r.host)
        return True, wildcard_ips
    except aiodns.error.DNSError:
        return False, wildcard_ips
