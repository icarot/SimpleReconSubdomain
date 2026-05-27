"""
Two-pass trusted resolver validation.

Inspired by PureDNS: after mass DNS brute-force with cheap public resolvers,
re-validate the discovered subdomains against a small set of trusted resolvers
(Google, Cloudflare).  This eliminates false positives caused by:

  - DNS poisoning on untrusted/open resolvers
  - Stale cached entries from public resolver pools
  - Load-balancing anomalies that pass wildcard filters

The trusted validation is rate-limited to avoid hitting resolver caps; default
concurrency is much lower than the brute-force phase.
"""

import asyncio

import aiodns

import core.colors as colors

TRUSTED_RESOLVERS: list[str] = [
    '8.8.8.8',    # Google Primary
    '8.8.4.4',    # Google Secondary
    '1.1.1.1',    # Cloudflare Primary
    '1.0.0.1',    # Cloudflare Secondary
]

_TRUSTED_CONCURRENCY = 50   # conservative; trusted resolvers enforce stricter limits
_RECORD_TYPES = ('A', 'AAAA', 'CNAME')


async def validate_with_trusted(
    subdomains: set[str],
    timeout: int = 5,
    concurrency: int = _TRUSTED_CONCURRENCY,
    verbose: int = 0,
    quiet: bool = False,
) -> set[str]:
    """
    Re-validate *subdomains* against trusted resolvers (Google / Cloudflare).

    Args:
        subdomains:   Set of candidate subdomains discovered by brute-force.
        timeout:      Per-query DNS timeout in seconds.
        concurrency:  Max concurrent DNS queries to trusted resolvers.
        verbose:      Verbosity level.
        quiet:        Suppress all output.

    Returns:
        Subset of *subdomains* that are confirmed by at least one trusted resolver.
    """
    if not subdomains:
        return set()

    validated: set[str] = set()
    semaphore = asyncio.Semaphore(concurrency)

    resolver = aiodns.DNSResolver(
        nameservers=TRUSTED_RESOLVERS,
        timeout=timeout,
    )

    if not quiet:
        print(colors.format_msg(
            f'[*] [validator] validating {len(subdomains)} subdomains '
            f'against trusted resolvers…'
        ))

    async def _check(subdomain: str) -> None:
        async with semaphore:
            for rtype in _RECORD_TYPES:
                try:
                    await resolver.query(subdomain, rtype)
                    validated.add(subdomain)
                    if verbose >= 1 and not quiet:
                        print(colors.format_msg(f'[+] [validator] confirmed: {subdomain} ({rtype})'))
                    return
                except aiodns.error.DNSError:
                    continue
            if verbose >= 2 and not quiet:
                print(colors.format_msg(f'[-] [validator] not confirmed: {subdomain}'))

    await asyncio.gather(*[_check(sub) for sub in subdomains])

    removed = len(subdomains) - len(validated)
    if not quiet and removed > 0:
        print(colors.format_msg(
            f'[*] [validator] removed {removed} unconfirmed subdomains '
            f'({len(validated)} remain)'
        ))

    return validated
