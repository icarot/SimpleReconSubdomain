import asyncio
from typing import Optional

import aiodns

import core.colors as colors

DEFAULT_RESOLVERS = [
    '8.8.8.8', '8.8.4.4',      # Google
    '1.1.1.1', '1.0.0.1',      # Cloudflare
    '9.9.9.9',                 # Quad9
    '208.67.222.222',          # OpenDNS
]

DEFAULT_RECORD_TYPES = ['A', 'AAAA', 'CNAME']


async def dns_bruteforce(
    domain: str,
    wordlist: Optional[str] = None,
    words: Optional[set[str]] = None,
    resolvers: Optional[list[str]] = None,
    concurrency: int = 200,
    record_types: Optional[list[str]] = None,
    verbose: int = 0,
    quiet: bool = False,
    wildcard: bool = False,
    wildcard_ips: Optional[set[str]] = None,
) -> set[str]:
    """
    Async DNS brute-force / resolution.

    Either *wordlist* (path to a file of prefixes) or *words* (a pre-built
    set of full subdomains from permutations) must be supplied.
    """
    if record_types is None:
        record_types = DEFAULT_RECORD_TYPES
    if resolvers is None or not resolvers:
        resolvers = DEFAULT_RESOLVERS
    if wildcard_ips is None:
        wildcard_ips = set()

    found: set[str] = set()
    semaphore = asyncio.Semaphore(concurrency)

    # Load word list from file when not supplied directly
    if words is None:
        if wordlist is None:
            return found
        try:
            with open(wordlist, 'r', errors='ignore') as fh:
                words = {
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith('#')
                }
        except FileNotFoundError:
            print(colors.format_msg(f'[!] Wordlist not found: {wordlist}'))
            return found

    if not words:
        return found

    if not quiet:
        print(colors.format_msg(f'[+] [brute] {len(words)} candidates → {domain}'))

    # Single shared resolver for efficiency
    resolver = aiodns.DNSResolver(nameservers=resolvers, timeout=3)

    async def resolve_candidate(candidate: str) -> None:
        # Permutations are already full hostnames; wordlist words are prefixes
        subdomain = (
            candidate
            if (candidate.endswith(f'.{domain}') or candidate == domain)
            else f'{candidate}.{domain}'
        )

        async with semaphore:
            errors: list[tuple[str, aiodns.error.DNSError]] = []
            for rtype in record_types:
                try:
                    result = await resolver.query(subdomain, rtype)
                    # Filter wildcard false positives (A-record check)
                    if wildcard and wildcard_ips and rtype == 'A':
                        resolved = {r.host for r in result}
                        if resolved.issubset(wildcard_ips):
                            if verbose >= 2 and not quiet:
                                print(colors.format_msg(f'[-] {subdomain} (wildcard filtered)'))
                            return
                    found.add(subdomain)
                    if verbose >= 1 and not quiet:
                        print(colors.format_msg(f'[+] {subdomain} ({rtype})'))
                    return
                except aiodns.error.DNSError as exc:
                    errors.append((rtype, exc))
                    continue

            # All record types exhausted without a valid result
            if verbose >= 1 and not quiet:
                if verbose >= 2:
                    detail = ', '.join(
                        f'{rt}:{str(e).strip() or type(e).__name__}'
                        for rt, e in errors
                    )
                    print(colors.format_msg(f'[-] {subdomain} (unresolved — {detail})'))
                    if verbose >= 4:
                        for rt, e in errors:
                            print(colors.format_msg(f'    [{rt}] {e!r}'))
                else:
                    print(colors.format_msg(f'[-] {subdomain} (unresolved)'))

    await asyncio.gather(*[resolve_candidate(w) for w in words])
    return found
