import asyncio
import re
import sys
from argparse import Namespace

import core.colors as colors
from core.dedup import DeduplicatedSet
from sources.passive.rapiddns import RapidDNS
from sources.passive.jldc import JLDC
from sources.passive.crtsh import CrtSh
from sources.passive.certspotter import CertSpotter
from sources.passive.urlscan import URLScan
from sources.passive.hackertarget import HackerTarget
from sources.passive.wayback import Wayback
from sources.passive.robtex import Robtex
from sources.passive.alienvault import AlienVault
from sources.passive.bufferover import BufferOver
from sources.passive.virustotal import VirusTotal
from sources.passive.securitytrails import SecurityTrails
from sources.passive.censys import Censys
from sources.passive.shodan import Shodan
from sources.active.zone_transfer import ZoneTransfer
from sources.active.dns_mining import DNSMining
from output.formatter import save_output

DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

ALL_PASSIVE_SOURCES: dict = {
    'rapiddns':     RapidDNS,
    'jldc':         JLDC,
    'crtsh':        CrtSh,
    'certspotter':  CertSpotter,
    'urlscan':      URLScan,
    'hackertarget': HackerTarget,
    'wayback':      Wayback,
    'robtex':       Robtex,
    'alienvault':      AlienVault,
    'bufferover':      BufferOver,
    'virustotal':      VirusTotal,       # requer API key
    'securitytrails':  SecurityTrails,   # requer API key
    'censys':          Censys,           # requer API key (censys_api_id + censys_api_secret)
    'shodan':          Shodan,           # requer API key
}

ALL_ACTIVE_SOURCES: dict = {
    'zone_transfer': ZoneTransfer,
    'dns_mining':    DNSMining,
}


def load_targets(domain: str | None = None, list_file: str | None = None) -> list[str]:
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


def load_resolvers(resolvers_file: str) -> list[str]:
    try:
        with open(resolvers_file, 'r') as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.startswith('#')
            ]
    except FileNotFoundError:
        print(colors.format_msg(f'[!] Resolvers file not found: {resolvers_file}'))
        return []


class Engine:
    def __init__(self, args: Namespace) -> None:
        self.args = args
        self.verbose: bool = getattr(args, 'verbose', False)
        self.quiet: bool = getattr(args, 'quiet', False)

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def log(self, msg: str) -> None:
        if not self.quiet:
            print(colors.format_msg(msg))

    def vlog(self, msg: str) -> None:
        if self.verbose and not self.quiet:
            print(colors.format_msg(msg))

    # ------------------------------------------------------------------
    # Source selection
    # ------------------------------------------------------------------

    def _select_sources(self) -> tuple[dict, dict]:
        if not self.args.sources:
            return ALL_PASSIVE_SOURCES, ALL_ACTIVE_SOURCES

        requested = {s.strip() for s in self.args.sources.split(',')}
        passive = {k: v for k, v in ALL_PASSIVE_SOURCES.items() if k in requested}
        active = {k: v for k, v in ALL_ACTIVE_SOURCES.items() if k in requested}
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
                self.vlog(f'  [{name}] 0 new subdomains')
        except Exception as exc:
            self.vlog(f'  [{name}] error: {exc}')
            source_counts[name] = 0

    # ------------------------------------------------------------------
    # Per-target enumeration
    # ------------------------------------------------------------------

    async def run_target(self, target: str) -> dict:
        self.log(f"\n{'-'*60}")
        self.log(f'[*] Enumerating: {target}')
        self.log(f"{'-'*60}")

        dedup = DeduplicatedSet()
        source_counts: dict = {}
        passive_sources, active_sources = self._select_sources()

        # ── Passive sources ──────────────────────────────────────────
        if not self.args.no_passive:
            self.log('[*] Running passive sources...')
            tasks = [
                self._run_source(name, cls(timeout=self.args.timeout), target, dedup, source_counts)
                for name, cls in passive_sources.items()
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        # ── Active sources (DNS-based) ────────────────────────────────
        if active_sources:
            self.log('[*] Running active sources...')
            for name, cls in active_sources.items():
                await self._run_source(
                    name, cls(timeout=self.args.timeout), target, dedup, source_counts
                )

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
                resolvers: list[str] = (
                    load_resolvers(self.args.resolvers) if self.args.resolvers else []
                )

                resolver = aiodns.DNSResolver()
                is_wildcard, wildcard_ips = await detect_wildcard(target, resolver)
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
                resolvers = (
                    load_resolvers(self.args.resolvers) if self.args.resolvers else []
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

        # ── Live host verification ─────────────────────────────────────
        live_results: dict = {}
        if self.args.verify_live and subdomains:
            from verify.live_check import verify_live
            self.log('[*] Verifying live hosts...')
            live_results = await verify_live(
                subdomains, timeout=self.args.timeout, quiet=self.quiet
            )
            live_count = sum(1 for v in live_results.values() if v.get('status'))
            self.log(f'[+] Live hosts: {live_count}/{len(subdomains)}')

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
