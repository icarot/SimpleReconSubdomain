import asyncio
import ipaddress
import random
import re
import sys
from argparse import Namespace

import httpx

import core.colors as colors
from core.dedup import DeduplicatedSet
from core.profiles import get_profile, profile_options
from sources import PASSIVE_SOURCES, ACTIVE_SOURCES
from output.formatter import save_output

DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

ALL_PASSIVE_SOURCES: dict = PASSIVE_SOURCES
ALL_ACTIVE_SOURCES: dict  = ACTIVE_SOURCES


def load_targets(domain: str | None = None, list_file: str | None = None, stdin: bool = False) -> list[str]:
    targets: list[str] = []
    if domain:
        targets.append(domain.strip().lower())
    if list_file:
        try:
            with open(list_file, 'r') as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line.lower())
        except FileNotFoundError:
            print(colors.format_msg(f'[!] File not found: {list_file}'))
            sys.exit(1)
    if stdin or (not domain and not list_file and not sys.stdin.isatty()):
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line.lower())

    valid: list[str] = []
    seen: set[str] = set()
    for t in targets:
        if t in seen:
            continue
        seen.add(t)
        if DOMAIN_PATTERN.match(t):
            valid.append(t)
        else:
            print(colors.format_msg(f'[!] Invalid domain skipped: {t}'))
    return valid


def load_resolvers(
    source: str,
    shuffle: bool = True,
    verbose: int = 0,
    quiet: bool = False,
) -> list[str]:
    """
    Load DNS resolver IPs from a local file or a remote URL.

    Accepts one entry per line; lines starting with '#' are comments.
    Entries may be bare IPs or in "ip:port" format — only the IP is kept.
    Both IPv4 and IPv6 addresses are accepted (aiodns handles both).
    Duplicates are removed and the list is shuffled by default so load is
    distributed across all resolvers rather than hammering the first few.

    Args:
        source:  Local file path or http(s):// URL.
        shuffle: Randomise the order of the returned list (default True).
        verbose: Verbosity level — level ≥1 prints count, ≥2 prints skipped entries.
        quiet:   Suppress all output.

    Returns:
        Deduplicated list of valid resolver IP strings.
    """
    lines: list[str] = []

    if source.startswith(('http://', 'https://')):
        # ── Remote URL ───────────────────────────────────────────────────
        try:
            resp = httpx.get(source, timeout=15, follow_redirects=True)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            if not quiet:
                print(colors.format_msg(
                    f'[*] [resolvers] Downloaded {len(lines)} lines from {source}'
                ))
        except Exception as exc:
            print(colors.format_msg(
                f'[!] [resolvers] Failed to download resolver list: {exc}'
            ))
            return []
    else:
        # ── Local file ───────────────────────────────────────────────────
        try:
            with open(source, 'r', errors='ignore') as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            print(colors.format_msg(f'[!] [resolvers] File not found: {source}'))
            return []

    valid: list[str] = []
    for line in lines:
        # Strip inline comments (e.g. "8.8.8.8  # Google")
        line = line.split('#')[0].strip()
        if not line:
            continue
        # Support "ip:port" format — keep only the IP part
        ip_part = line.split(':')[0].strip()
        try:
            addr = ipaddress.ip_address(ip_part)
            valid.append(str(addr))
        except ValueError:
            if verbose >= 2 and not quiet:
                print(colors.format_msg(
                    f'[-] [resolvers] Skipping invalid entry: {line!r}'
                ))

    # Deduplicate while preserving order before shuffle
    seen: dict[str, None] = {}
    for ip in valid:
        seen[ip] = None
    valid = list(seen.keys())

    if shuffle:
        random.shuffle(valid)

    if not quiet and (verbose >= 1):
        print(colors.format_msg(
            f'[*] [resolvers] Loaded {len(valid)} valid resolver IPs'
        ))

    return valid


class Engine:
    def __init__(self, args: Namespace) -> None:
        self.args = args
        self.verbose: int = getattr(args, 'verbose', 0) or 0
        self.quiet: bool = getattr(args, 'quiet', False)

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def log(self, msg: str) -> None:
        if not self.quiet:
            print(colors.format_msg(msg))

    def vlog(self, level: int, msg: str) -> None:
        if self.verbose >= level and not self.quiet:
            print(colors.format_msg(msg))

    # ------------------------------------------------------------------
    # Source selection
    # ------------------------------------------------------------------

    def _select_sources(self) -> tuple[dict, dict]:
        # --profile takes precedence over --sources
        profile_name: str | None = getattr(self.args, 'profile', None)
        if profile_name:
            profile = get_profile(profile_name)
            if profile is None:
                self.log(f'[!] Unknown profile: {profile_name!r} — running all sources')
                passive, active = ALL_PASSIVE_SOURCES, ALL_ACTIVE_SOURCES
            else:
                sources = profile.get('sources', 'all')
                # Apply profile-level option defaults (only if not explicitly set by CLI)
                opts = profile_options(profile_name)
                if opts.get('rate_limit') and not getattr(self.args, 'rate_limit', None):
                    self.args.rate_limit = opts['rate_limit']
                if sources == 'all' or sources is None:
                    passive, active = ALL_PASSIVE_SOURCES, ALL_ACTIVE_SOURCES
                else:
                    requested = set(sources)
                    passive = {k: v for k, v in ALL_PASSIVE_SOURCES.items() if k in requested}
                    active = {k: v for k, v in ALL_ACTIVE_SOURCES.items() if k in requested}
        elif self.args.sources:
            requested = {s.strip() for s in self.args.sources.split(',')}
            passive = {k: v for k, v in ALL_PASSIVE_SOURCES.items() if k in requested}
            active = {k: v for k, v in ALL_ACTIVE_SOURCES.items() if k in requested}
            unknown = requested - set(ALL_PASSIVE_SOURCES) - set(ALL_ACTIVE_SOURCES)
            for name in sorted(unknown):
                self.log(f'[!] Unknown source: {name!r} — skipping')
        else:
            passive, active = ALL_PASSIVE_SOURCES, ALL_ACTIVE_SOURCES

        # Apply --exclude (works regardless of how sources were selected)
        exclude = {
            s.strip()
            for s in (getattr(self.args, 'exclude', '') or '').split(',')
            if s.strip()
        }
        if exclude:
            passive = {k: v for k, v in passive.items() if k not in exclude}
            active = {k: v for k, v in active.items() if k not in exclude}

        return passive, active

    # ------------------------------------------------------------------
    # Single-source runner (async, exception-safe)
    # ------------------------------------------------------------------

    async def _run_source(
        self,
        name: str,
        source,
        target: str,
        dedup: DeduplicatedSet,
        source_counts: dict,
    ) -> None:
        try:
            found = await source.fetch(target)
            new_items = dedup.update(found)
            source_counts[name] = len(new_items)
            if new_items:
                self.log(f'[*] [{name}] +{len(new_items)} subdomains')
            else:
                self.vlog(1, f'[!] [{name}] 0 new subdomains')
        except Exception as exc:
            self.vlog(1, f'[x] [{name}] error: {exc}')
            source_counts[name] = 0

    # ------------------------------------------------------------------
    # Per-target enumeration
    # ------------------------------------------------------------------

    async def run_target(
        self,
        target: str,
        _seen_targets: set[str] | None = None,
        _depth: int = 0,
    ) -> dict:
        self.log(f"\n{'-'*60}")
        self.log(f'[*] Enumerating: {target}')
        self.log(f"{'-'*60}")

        dedup = DeduplicatedSet()
        source_counts: dict = {}
        passive_sources, active_sources = self._select_sources()
        rate_limit: int = getattr(self.args, 'rate_limit', 0) or 0
        proxy: str | None = getattr(self.args, 'proxy', None)
        user_agent: str = getattr(self.args, 'user_agent', 'SimpleReconSubdomain/2') or 'SimpleReconSubdomain/2'
        resolvers: list[str] = []  # shared across brute-force and permutation

        def _make_source(cls):
            return cls(
                timeout=self.args.timeout,
                rate_limit=rate_limit,
                verbose=self.verbose,
                proxy=proxy,
                user_agent=user_agent,
            )

        # ── Passive sources ──────────────────────────────────────────
        if not self.args.no_passive:
            self.log('[*] Running passive sources...')
            tasks = [
                self._run_source(name, _make_source(cls), target, dedup, source_counts)
                for name, cls in passive_sources.items()
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        # ── Active sources (DNS-based) ────────────────────────────────
        if active_sources:
            self.log('[*] Running active sources...')
            active_tasks = [
                self._run_source(name, _make_source(cls), target, dedup, source_counts)
                for name, cls in active_sources.items()
            ]
            await asyncio.gather(*active_tasks, return_exceptions=True)

        # ── DNS brute-force ───────────────────────────────────────────
        if self.args.brute:
            try:
                import aiodns
                from bruteforce.resolver import dns_bruteforce
                from bruteforce.wildcard import detect_wildcard
            except ImportError:
                print(colors.format_msg('[!] aiodns is required for brute-force. Run: pip install aiodns'))
                self.args.brute = None
            else:
                self.log('[*] Starting DNS brute-force...')
                resolvers = (
                    load_resolvers(
                        self.args.resolvers,
                        verbose=self.verbose,
                        quiet=self.quiet,
                    )
                    if self.args.resolvers else []
                )

                # ── Optional resolver health check (PureDNS technique) ────
                if getattr(self.args, 'check_resolvers', False) and resolvers:
                    from bruteforce.resolver_check import check_resolvers
                    self.log('[*] Running resolver health check...')
                    resolvers = await check_resolvers(
                        resolvers,
                        verbose=self.verbose,
                        quiet=self.quiet,
                    )
                    if not resolvers:
                        self.log('[!] No working resolvers found — falling back to defaults')

                wildcard_tests: int = getattr(self.args, 'wildcard_tests', 3) or 3
                # Use custom resolvers for wildcard detection too (bug fix)
                resolver = aiodns.DNSResolver(
                    nameservers=resolvers if resolvers else None,
                    timeout=3,
                )
                is_wildcard, wildcard_ips = await detect_wildcard(
                    target, resolver, tests=wildcard_tests, verbose=self.verbose
                )
                if is_wildcard:
                    self.log(f'[!] Wildcard DNS detected on {target} - filtering false positives')

                brute_found = await dns_bruteforce(
                    domain=target,
                    wordlist=self.args.brute,
                    resolvers=resolvers or None,
                    concurrency=self.args.threads * 25,
                    verbose=self.verbose,
                    quiet=self.quiet,
                    wildcard=is_wildcard,
                    wildcard_ips=wildcard_ips,
                )

                # ── Two-pass trusted resolver validation (PureDNS technique) ──
                if getattr(self.args, 'validate_resolvers', False) and brute_found:
                    from bruteforce.validator import validate_with_trusted
                    self.log('[*] Running two-pass trusted resolver validation...')
                    brute_found = await validate_with_trusted(
                        brute_found,
                        timeout=self.args.timeout,
                        verbose=self.verbose,
                        quiet=self.quiet,
                    )

                new_items = dedup.update(brute_found)
                source_counts['bruteforce'] = len(new_items)
                self.log(f'[*] [bruteforce] +{len(new_items)} new subdomains')

        # ── Permutation ───────────────────────────────────────────────
        if self.args.permute and len(dedup) > 0:
            try:
                import aiodns
                from bruteforce.resolver import dns_bruteforce
                from bruteforce.permutation import generate_permutations
            except ImportError:
                print(colors.format_msg('[!] aiodns is required for permutation. Run: pip install aiodns'))
            else:
                self.log('[*] Generating subdomain permutations...')
                perms = generate_permutations(dedup.as_set(), target)
                self.log(f'[*] Generated {len(perms)} candidates - resolving...')
                if not resolvers and self.args.resolvers:
                    resolvers = load_resolvers(
                        self.args.resolvers,
                        verbose=self.verbose,
                        quiet=self.quiet,
                    )
                perm_found = await dns_bruteforce(
                    domain=target,
                    words=perms,
                    resolvers=resolvers or None,
                    concurrency=self.args.threads * 25,
                    verbose=self.verbose,
                    quiet=self.quiet,
                    wildcard=False,
                )
                new_items = dedup.update(perm_found)
                source_counts['permutation'] = len(new_items)
                self.log(f'[*] [permutation] +{len(new_items)} new subdomains')

        subdomains = dedup.as_set()
        self.log(f'\n[+] Total unique subdomains found: {len(subdomains)}')

        # ── Live host verification + TLS SAN extraction ───────────────
        live_results: dict = {}
        if self.args.verify_live and subdomains:
            from verify.live_check import verify_live
            self.log('[*] Verifying live hosts...')
            live_results = await verify_live(
                subdomains,
                timeout=self.args.timeout,
                quiet=self.quiet,
                concurrency=self.args.threads * 5,
            )
            live_count = sum(1 for v in live_results.values() if v.get('status'))
            self.log(f'[+] Live hosts: {live_count}/{len(subdomains)}')

            # Harvest new subdomains from TLS SANs (Amass technique)
            san_candidates: set[str] = set()
            for host_info in live_results.values():
                for san in host_info.get('tls_sans', []):
                    san_clean = san.lstrip('*.').strip().lower()
                    if san_clean and (san_clean == target or san_clean.endswith(f'.{target}')):
                        san_candidates.add(san_clean)

            if san_candidates:
                new_from_sans = dedup.update(san_candidates)
                if new_from_sans:
                    source_counts['tls_sans'] = len(new_from_sans)
                    self.log(f'[*] [tls_sans] +{len(new_from_sans)} new subdomains from certificates')
                    subdomains = dedup.as_set()

        # ── Recursive enumeration (Subfinder --recursive technique) ───
        recursive: bool = getattr(self.args, 'recursive', False)
        recursive_depth: int = getattr(self.args, 'recursive_depth', 1) or 1

        if recursive and _depth < recursive_depth:
            if _seen_targets is None:
                _seen_targets = {target}
            else:
                _seen_targets.add(target)

            # Only recurse into subdomains with 3+ labels (actual subdomains)
            recurse_candidates = {
                sub for sub in subdomains
                if sub.count('.') > target.count('.') + 0
                and sub not in _seen_targets
                and DOMAIN_PATTERN.match(sub)
            }

            if recurse_candidates:
                self.log(
                    f'[*] [recursive] depth {_depth + 1}/{recursive_depth} — '
                    f'enumerating {len(recurse_candidates)} subdomains'
                )
                for sub_target in sorted(recurse_candidates):
                    if sub_target in _seen_targets:
                        continue
                    _seen_targets.add(sub_target)
                    sub_result = await self.run_target(
                        sub_target,
                        _seen_targets=_seen_targets,
                        _depth=_depth + 1,
                    )
                    # Merge recursive findings back into current dedup set
                    new_recursive = dedup.update(sub_result['subdomains'])
                    if new_recursive:
                        source_counts[f'recursive:{sub_target}'] = len(new_recursive)
                        self.log(
                            f'[*] [recursive] +{len(new_recursive)} new subdomains '
                            f'from {sub_target}'
                        )

                subdomains = dedup.as_set()

        return {
            'domain': target,
            'subdomains': subdomains,
            'live': live_results,
            'sources': source_counts,
        }

    # ------------------------------------------------------------------
    # Main entrypoint
    # ------------------------------------------------------------------

    async def run(self) -> None:
        targets = load_targets(
            domain=self.args.domain,
            list_file=self.args.list,
            stdin=getattr(self.args, 'stdin', False),
        )

        if not targets:
            print(colors.format_msg('[!] No valid targets found.'))
            sys.exit(1)

        all_results: list[dict] = []
        for target in targets:
            result = await self.run_target(target)
            all_results.append(result)

        save_output(
            results=all_results,
            fmt=self.args.output,
            outfile=getattr(self.args, 'outfile', None),
            quiet=self.quiet,
        )
