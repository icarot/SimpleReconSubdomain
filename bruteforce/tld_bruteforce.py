"""
TLD brute force — discover live variants of the target domain under different TLDs.

Given target `example.com`, strips the TLD to get the base (`example`), then
resolves `example.{tld}` for every TLD in the wordlist. Returns the set of
hostnames that produce at least one A or AAAA DNS record.

Results are NOT subdomains of the target domain; the engine stores them in a
separate `tld_variants` key in the result dict.
"""
from __future__ import annotations

import asyncio
import os
from typing import Optional

_DEFAULT_TLD_LIST = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 'config', 'tlds.txt'
)


def _load_tlds(path: str) -> list[str]:
    tlds: list[str] = []
    try:
        with open(path, 'r', errors='ignore') as fh:
            for line in fh:
                line = line.split('#')[0].strip().lstrip('.')
                if line:
                    tlds.append(line.lower())
    except FileNotFoundError:
        pass
    return tlds


def _extract_base(domain: str, known_tlds: list[str] | None = None) -> str:
    """Return the registrable base label, stripping the current TLD.

    When *known_tlds* is supplied (the loaded wordlist), the function tries to
    match the longest compound TLD in the list so that exotic SLDs like
    .ong.br, .adv.br, .co.uk are handled automatically.

    Fallback when no list is available: heuristic using a set of common SLD prefixes.
    """
    parts = domain.rstrip('.').split('.')
    if len(parts) <= 1:
        return domain

    domain_lower = domain.lower().rstrip('.')

    if known_tlds:
        # Try compound TLDs first (longest match wins)
        compound = sorted(
            (t for t in known_tlds if '.' in t),
            key=len, reverse=True,
        )
        for tld in compound:
            suffix = f'.{tld}'
            if domain_lower.endswith(suffix):
                base = domain_lower[: -len(suffix)]
                if base:
                    return base

    # Heuristic fallback: common SLD prefixes that signal a compound TLD
    _COMPOUND_SECOND = {
        'co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne',
        'ltd', 'plc', 'mil', 'gob', 'gub', 'go', 'ong', 'adv', 'ind',
        'pro', 'rec', 'tmp', 'srv', 'med', 'leg', 'jus', 'inf',
    }
    if len(parts) >= 3 and parts[-2] in _COMPOUND_SECOND:
        return '.'.join(parts[:-2])

    # Standard: foo.com → base = foo
    return '.'.join(parts[:-1])


async def tld_bruteforce(
    domain: str,
    tld_file: Optional[str] = None,
    concurrency: int = 100,
    timeout: float = 5.0,
    verbose: int = 0,
    quiet: bool = False,
) -> set[str]:
    """Resolve {base}.{tld} for every TLD in the wordlist.

    Args:
        domain:      Target domain (e.g. "example.com").
        tld_file:    Path to TLD wordlist. Defaults to config/tlds.txt.
        concurrency: Max simultaneous DNS resolutions.
        timeout:     Per-query timeout in seconds.
        verbose:     Verbosity level.
        quiet:       Suppress all output.

    Returns:
        Set of hostnames that resolved successfully (e.g. {"example.net", "example.io"}).
        The original domain is excluded from results.
    """
    import aiodns

    tlds = _load_tlds(tld_file or _DEFAULT_TLD_LIST)
    if not tlds:
        if not quiet:
            print('[!] [tld_brute] No TLDs loaded — check config/tlds.txt')
        return set()

    base = _extract_base(domain, known_tlds=tlds)
    if not base:
        return set()

    if not quiet and verbose >= 1:
        print(f'[*] [tld_brute] Base: {base!r} — testing {len(tlds)} TLDs')

    resolver = aiodns.DNSResolver(timeout=timeout)
    semaphore = asyncio.Semaphore(concurrency)
    found: set[str] = set()

    async def _resolve(candidate: str) -> None:
        async with semaphore:
            for qtype in ('A', 'AAAA'):
                try:
                    result = await resolver.query(candidate, qtype)
                    if result:
                        found.add(candidate)
                        if not quiet and verbose >= 1:
                            print(f'[+] [tld_brute] {candidate} resolved ({qtype})')
                        return
                except Exception:
                    pass

    candidates = [f'{base}.{tld}' for tld in tlds if f'{base}.{tld}' != domain]

    await asyncio.gather(*[_resolve(c) for c in candidates])

    return found
