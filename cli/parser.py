import argparse

from core.profiles import load_profiles, profile_names
from sources import PASSIVE_SOURCES, ACTIVE_SOURCES

# Built dynamically from the auto-discovered source modules
ALL_PASSIVE = list(PASSIVE_SOURCES)
ALL_ACTIVE  = list(ACTIVE_SOURCES)
ALL_SOURCES = ALL_PASSIVE + ALL_ACTIVE


class _ColoredFormatter(argparse.RawDescriptionHelpFormatter):
    """Argparse formatter with ANSI color support."""

    def start_section(self, heading: str | None) -> None:
        import core.colors as C
        if heading:
            heading = C.bold(C.cyan(heading))
        super().start_section(heading)

    def _format_usage(self, usage, actions, groups, prefix):
        import core.colors as C
        return super()._format_usage(
            usage, actions, groups,
            prefix if prefix is not None else C.bold(C.cyan('usage')) + ': ',
        )

    def _format_action_invocation(self, action) -> str:
        import core.colors as C
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            metavar, = self._metavar_formatter(action, default)(1)
            return C.cyan(metavar)
        parts = []
        if action.nargs == 0:
            parts.extend(C.cyan(s) for s in action.option_strings)
        else:
            default = self._get_default_metavar_for_optional(action)
            args_string = self._format_args(action, default)
            for option_string in action.option_strings:
                parts.append(f'{C.cyan(option_string)} {C.yellow(args_string)}')
        return ', '.join(parts)


def build_parser() -> argparse.ArgumentParser:
    import core.colors as C

    description = (
        f'{C.bold(C.white("SimpleReconSubdomain v2"))}'
        ' - Passive + Active subdomain enumeration'
    )
    epilog = (
        f'{C.bold(C.cyan("quick start:"))}\n'
        f'  {C.gray("python simplerecon.py -d target.com --profile fast")}\n'
        f'  {C.gray("python simplerecon.py -d target.com --profile osint --verify-live")}\n'
        f'\n'
        f'{C.bold(C.cyan("see more:"))}\n'
        f'  {C.gray("python simplerecon.py --list-sources")}    {C.gray("# all sources")}\n'
        f'  {C.gray("python simplerecon.py --list-profiles")}   {C.gray("# curated source groups")}\n'
        f'  {C.gray("python simplerecon.py --list-examples")}   {C.gray("# usage examples + tool chaining")}\n'
    )

    parser = argparse.ArgumentParser(
        prog='simplerecon.py',
        description=description,
        formatter_class=_ColoredFormatter,
        epilog=epilog,
    )

    # Target
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        '-d', '--domain', metavar='DOMAIN', help='Single target domain'
    )
    target_group.add_argument(
        '-l', '--list', metavar='FILE', help='File with list of target domains'
    )
    target_group.add_argument(
        '--stdin',
        action='store_true',
        help='Read target domains from stdin (one per line); enables pipe-friendly use',
    )

    # Output
    parser.add_argument(
        '-o', '--output',
        choices=['txt', 'json', 'csv', 'ndjson', 'html', 'markdown'],
        default='txt',
        help='Output format (default: txt). ndjson = one JSON line per subdomain; '
             'html = interactive network-map page; markdown = human-readable report',
    )
    parser.add_argument('--outfile', metavar='FILE', help='Write output to file')
    parser.add_argument(
        '--network-map',
        action='store_true',
        help='Include network graph (nodes/edges) in JSON output. '
             'Auto-enabled when -o html or --network-html is used.',
    )
    parser.add_argument(
        '--network-html',
        metavar='FILE',
        help='Write an HTML network-map visualization to FILE alongside the main output. '
             'Combine with any -o format.',
    )

    # Discovery helpers
    parser.add_argument(
        '--learn-words',
        action='store_true',
        help='Derive additional brute-force candidates from discovered subdomain patterns '
             '(numeric sequences, environment families, geo variants, version bumps). '
             'Runs after passive/active gathering, before --brute.',
    )

    # Performance
    parser.add_argument(
        '-t', '--threads',
        type=int, default=8,
        help='Thread multiplier for brute-force concurrency (default: 8)',
    )
    parser.add_argument(
        '--timeout',
        type=int, default=30,
        help='HTTP/DNS timeout in seconds (default: 30)',
    )
    parser.add_argument(
        '--rate-limit',
        type=int, default=0,
        metavar='N',
        help='Max concurrent requests per passive source (0=unlimited)',
    )

    # Source control
    parser.add_argument(
        '--profile',
        metavar='PROFILE',
        help=(
            'Run a predefined source group. Available: '
            + ', '.join(profile_names())
            + '. Overrides --sources if both are given.'
        ),
    )
    parser.add_argument(
        '--sources',
        metavar='SOURCES',
        help=f'Comma-separated sources to use (default: all). Available: {", ".join(ALL_SOURCES)}',
    )
    parser.add_argument(
        '--exclude',
        metavar='SOURCES',
        help='Comma-separated sources to exclude. Applied after --sources/--profile selection',
    )
    parser.add_argument(
        '--no-passive',
        action='store_true',
        help='Skip all passive sources (brute-force / active only)',
    )
    parser.add_argument(
        '--list-sources',
        action='store_true',
        help='List all available sources and exit',
    )
    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='List all available profiles and exit',
    )
    parser.add_argument(
        '--list-examples',
        action='store_true',
        help='Print categorized usage examples (incl. tool chaining) and exit',
    )

    # Run-config preset
    parser.add_argument(
        '--config',
        metavar='FILE',
        help=(
            'JSON file with CLI argument presets (run-config). '
            'Explicit CLI flags always override values from the config file. '
            'See config/run_config.example.json for the full format.'
        ),
    )

    # Brute-force
    parser.add_argument(
        '--brute', metavar='WORDLIST', help='Wordlist path for DNS brute-force'
    )
    parser.add_argument(
        '--resolvers', metavar='FILE_OR_URL',
        help=(
            'File or URL with DNS resolver IPs, one per line '
            '(e.g. config/resolvers.txt or https://public-dns.info/nameservers-all.txt). '
            'Resolvers are shuffled automatically for load distribution.'
        ),
    )
    parser.add_argument(
        '--check-resolvers',
        action='store_true',
        help=(
            'Test each resolver against example.com before brute-force and remove '
            'non-responsive ones (PureDNS technique). Adds startup time but improves '
            'accuracy when using large community resolver lists.'
        ),
    )
    parser.add_argument(
        '--permute',
        action='store_true',
        help='Generate and resolve Altdns-style subdomain permutations',
    )
    parser.add_argument(
        '--wildcard-tests',
        type=int, default=3,
        metavar='N',
        help=(
            'Number of random probes for wildcard DNS detection (default: 3). '
            'Higher values reduce false negatives on load-balanced DNS (PureDNS technique).'
        ),
    )
    parser.add_argument(
        '--validate-resolvers',
        action='store_true',
        help=(
            'After brute-force, re-validate results against trusted resolvers '
            '(Google/Cloudflare) to eliminate DNS-poisoned false positives (PureDNS two-pass technique).'
        ),
    )

    # Extras — out-of-scope elements
    parser.add_argument(
        '--show-extras',
        action='store_true',
        help=(
            'Surface elements found during enumeration that fall outside the target domain: '
            'external hosts (from certs, code, APIs), IPs (from --verify-live), '
            'and crawled URLs (from spider). Shown as separate sections in all output formats.'
        ),
    )

    # TLD brute-force
    parser.add_argument(
        '--tld-brute',
        nargs='?',
        const='',
        metavar='FILE',
        help=(
            'Discover live TLD variants of the target base domain '
            '(e.g. target.net, target.io). '
            'Optional FILE overrides the default config/tlds.txt wordlist. '
            'Results are reported separately from subdomains.'
        ),
    )

    # Post-processing
    parser.add_argument(
        '--verify-live',
        action='store_true',
        help='Verify which subdomains respond to HTTP/HTTPS and extract TLS certificate SANs (Amass technique)',
    )
    parser.add_argument(
        '--recursive',
        action='store_true',
        help=(
            'Re-enumerate discovered subdomains as targets to find deeper sub-subdomains '
            '(Subfinder --recursive technique).'
        ),
    )
    parser.add_argument(
        '--recursive-depth',
        type=int, default=1,
        metavar='N',
        help='Maximum recursion depth when --recursive is enabled (default: 1)',
    )

    # Verbosity
    parser.add_argument(
        '-v', '--verbose',
        nargs='?', const=1, type=int, default=0,
        metavar='LEVEL',
        help='Verbose level (cumulativo): 1=zero results, 2=+HTTP codes, 3=+HTTP body, 4=full debug+exceptions',
    )
    parser.add_argument(
        '-q', '--quiet', action='store_true', help='Quiet mode (results only)'
    )
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress banner and all process output; print only the final subdomain list',
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable ANSI color output',
    )

    # Network / proxy
    parser.add_argument(
        '--proxy',
        metavar='URL',
        help='Route all HTTP requests through this proxy (e.g. http://127.0.0.1:8080 or socks5://host:port)',
    )
    parser.add_argument(
        '--user-agent',
        metavar='UA',
        default='SimpleReconSubdomain/2',
        help='Override the HTTP User-Agent header sent by all sources (default: SimpleReconSubdomain/2)',
    )

    return parser


def print_sources() -> None:
    import core.colors as C

    def _key_badge(cls) -> str:
        if cls.API_TOKEN_IS_REQUIREMENT:
            return C.red('[API key obrigatória]')
        return ''

    print(f'\n{C.bold(C.white("Available sources:"))}\n')
    print(f'  {C.bold(C.cyan("PASSIVE"))} ')
    for cls in PASSIVE_SOURCES.values():
        badge = _key_badge(cls)
        suffix = f'  {badge}' if badge else ''
        print(f'    {C.cyan(f"{cls.NAME:<16}")} {cls.DESCRIPTION}{suffix}')
    print(f'\n  {C.bold(C.cyan("ACTIVE"))} {C.gray("(DNS-based):")}')
    for cls in ACTIVE_SOURCES.values():
        print(f'    {C.cyan(f"{cls.NAME:<16}")} {cls.DESCRIPTION}')
    print()


def print_profiles() -> None:
    import core.colors as C

    profiles = load_profiles()
    if not profiles:
        print('No profiles found.')
        return

    print(f'\n{C.bold(C.white("Available profiles:"))}\n')
    for name, cfg in profiles.items():
        sources = cfg.get('sources', 'all')
        if isinstance(sources, list):
            src_str = ', '.join(sources)
        else:
            src_str = str(sources)
        opts = cfg.get('options', {})
        opts_str = f'  {C.gray(str(opts))}' if opts else ''
        print(f'  {C.cyan(f"{name:<12}")} {cfg.get("description", "")}')
        print(f'  {" " * 12} {C.gray("sources:")} {src_str}{opts_str}')
    print()


# ---------------------------------------------------------------------------
# Categorized usage examples (printed via --list-examples)
# ---------------------------------------------------------------------------
_EXAMPLES: list[tuple[str, list[str]]] = [
    ('Basics', [
        'python simplerecon.py -d target.com',
        'python simplerecon.py -l domains.txt',
        'python simplerecon.py --list-sources',
        'python simplerecon.py --list-profiles',
        'python simplerecon.py --list-examples',
    ]),
    ('Profiles (curated source groups)', [
        'python simplerecon.py -d target.com --profile fast',
        'python simplerecon.py -d target.com --profile stealth --verify-live',
        'python simplerecon.py -d target.com --profile osint --output json --outfile osint.json',
        'python simplerecon.py -d target.com --profile code -v 2',
        'python simplerecon.py -d target.com --profile active --no-passive',
        'python simplerecon.py -d target.com --profile full --recursive --recursive-depth 2',
    ]),
    ('Custom source selection', [
        'python simplerecon.py -d target.com --sources crtsh,hackertarget,wayback',
        'python simplerecon.py -d target.com --sources github,grep_app,urlscan',
        'python simplerecon.py -d target.com --sources nsec_walk,srv_enum,js_scrape',
        'python simplerecon.py -d target.com --sources anubisdb,merklemap,subdomaincenter,threatminer',
    ]),
    ('Output formats', [
        'python simplerecon.py -d target.com --output json --outfile result.json',
        'python simplerecon.py -d target.com --output csv  --outfile result.csv',
        'python simplerecon.py -d target.com --output txt  --outfile result.txt',
        'python simplerecon.py -d target.com --no-banner > subs.txt',
    ]),
    ('Performance & rate-limiting', [
        'python simplerecon.py -d target.com --threads 20',
        'python simplerecon.py -d target.com --rate-limit 5 --timeout 15',
        'python simplerecon.py -d target.com --profile osint --rate-limit 3',
        'python simplerecon.py -l domains.txt --threads 40 --timeout 60',
    ]),
    ('Live verification (HTTP + TLS SAN + takeover detection)', [
        'python simplerecon.py -d target.com --verify-live --timeout 10',
        'python simplerecon.py -d target.com --profile fast --verify-live -o json --outfile live.json',
        'python simplerecon.py -d target.com --verify-live -o csv --outfile live.csv',
    ]),
    ('DNS brute-force', [
        'python simplerecon.py -d target.com --brute wordlist.txt --threads 20',
        'python simplerecon.py -d target.com --brute wordlist.txt --resolvers config/resolvers.txt',
        'python simplerecon.py -d target.com --brute wordlist.txt \\\n       --resolvers https://public-dns.info/nameservers-all.txt --check-resolvers',
        'python simplerecon.py -d target.com --brute wordlist.txt --wildcard-tests 5 --validate-resolvers',
        'python simplerecon.py -d target.com --no-passive --brute wordlist.txt',
    ]),
    ('Permutations and recursive enumeration', [
        'python simplerecon.py -d target.com --permute',
        'python simplerecon.py -d target.com --recursive --recursive-depth 2',
        'python simplerecon.py -d target.com --recursive --recursive-depth 2 --verify-live',
    ]),
    ('Debug & verbosity', [
        'python simplerecon.py -d target.com --sources crtsh -v 4',
        'python simplerecon.py -d target.com --profile fast --quiet',
        'python simplerecon.py -d target.com -v 2     # show HTTP status codes',
        'python simplerecon.py -d target.com -v 4     # full debug + exceptions',
    ]),
    ('Piping into httpx (HTTP probing)', [
        'python simplerecon.py -d target.com --no-banner | httpx -silent',
        'python simplerecon.py -d target.com --no-banner | httpx -silent -mc 200',
        'python simplerecon.py -d target.com --no-banner | httpx -silent -status-code -title -tech-detect',
        'python simplerecon.py -d target.com --no-banner | httpx -silent -mc 200,301,302 -title',
    ]),
    ('Piping into nuclei (vulnerability scanning)', [
        'python simplerecon.py -d target.com --no-banner | httpx -silent | nuclei -t cves/ -silent',
        'python simplerecon.py -d target.com --no-banner | httpx -silent | nuclei -severity critical,high',
        'python simplerecon.py -d target.com --profile osint --no-banner | httpx -silent | nuclei -t exposures/',
    ]),
    ('Piping into dnsx (DNS resolution + CNAME)', [
        'python simplerecon.py -d target.com --no-banner | dnsx -silent -a -resp',
        'python simplerecon.py -d target.com --no-banner | dnsx -silent -cname -resp',
        '# detect potential takeovers via CNAME chain',
        'python simplerecon.py -d target.com --no-banner | dnsx -silent -cname -resp \\\n       | grep -E "amazonaws|azurewebsites|github.io|herokuapp|netlify|cloudfront"',
    ]),
    ('Piping into nmap (port scanning)', [
        'python simplerecon.py -d target.com --no-banner > subs.txt && nmap -iL subs.txt -p 80,443,8080,8443 -T4 --open',
        'python simplerecon.py -d target.com --no-banner | dnsx -silent -a -resp-only \\\n       | sort -u | nmap -iL - -p- -T4 --open',
    ]),
    ('Piping into katana / gospider (crawling)', [
        'python simplerecon.py -d target.com --no-banner | httpx -silent | katana -silent',
        'python simplerecon.py -d target.com --no-banner | httpx -silent | gau --threads 10',
    ]),
    ('Screenshots (eyewitness / gowitness / aquatone)', [
        'python simplerecon.py -d target.com --verify-live -o txt --outfile subs.txt && \\\n       eyewitness --web -f subs.txt --no-prompt -d screenshots/',
        'python simplerecon.py -d target.com --no-banner | httpx -silent | gowitness scan single',
        'python simplerecon.py -d target.com --no-banner | aquatone -out aquatone-report/',
    ]),
    ('Takeover hunting (verify-live + jq + dnsx)', [
        'python simplerecon.py -d target.com --verify-live -o json --outfile out.json',
        '# extract candidates flagged as takeover-vulnerable',
        'jq -r \'.live_hosts | to_entries[] | select(.value.takeover != null) | "\\(.key)\\t\\(.value.takeover)"\' out.json',
        '# confirm dangling CNAME for each candidate',
        'jq -r \'.live_hosts | to_entries[] | select(.value.takeover) | .key\' out.json \\\n       | dnsx -silent -cname -resp',
    ]),
    ('TLD brute force', [
        'python simplerecon.py -d target.com --tld-brute',
        'python simplerecon.py -d target.com --tld-brute custom_tlds.txt',
        'python simplerecon.py -d target.com --tld-brute -o json --outfile result.json',
    ]),
    ('Run-config presets (--config)', [
        'cp config/run_config.example.json myrun.json',
        '# edit myrun.json with your preferred options',
        'python simplerecon.py -d target.com --config myrun.json',
        '# CLI flags override config values:',
        'python simplerecon.py -d target.com --config myrun.json --output txt',
    ]),
    ('Asset discovery from a domain list', [
        'python simplerecon.py -l scope.txt --output json --outfile all_subs.json --timeout 60',
        'python simplerecon.py -l scope.txt --profile osint --verify-live --rate-limit 3',
        'cat scope.txt | xargs -I{} python simplerecon.py -d {} --no-banner | sort -u > all_unique.txt',
    ]),
    ('Continuous monitoring (diff against previous run)', [
        'python simplerecon.py -d target.com --no-banner | sort -u > today.txt',
        'comm -13 <(sort -u yesterday.txt) today.txt   # show only new subs',
    ]),
    ('string-x (strx) — modular pipeline automation [github.com/MrCl0wnLab/string-x]', [
        '# HTTP probe each discovered subdomain through strx',
        'python simplerecon.py -d target.com --no-banner \\\n       | strx -st "echo {STRING}" -module "clc:http_probe" -pm',
        '# resolve subs -> extract IPs -> Shodan lookup per IP',
        'python simplerecon.py -d target.com --no-banner \\\n       | strx -st "echo {STRING}" -module "clc:dns" -pm \\\n       | strx -st "echo {STRING}" -module "ext:ip" -pm \\\n       | strx -st "echo {STRING}" -module "clc:shodan" -pm',
        '# DNS + IP extraction + geo-IP enrichment in a single chain',
        'python simplerecon.py -d target.com --no-banner \\\n       | strx -st "echo {STRING}" -module "clc:dns|ext:ip|clc:geoip" -pm',
        '# scrape each live host and extract emails',
        'python simplerecon.py -d target.com --verify-live --no-banner \\\n       | strx -st "curl -sk https://{STRING}" -module "ext:email" -pm',
        '# extract URLs from each subdomain and pipe to nuclei',
        'python simplerecon.py -d target.com --no-banner \\\n       | strx -st "curl -sk https://{STRING}" -module "ext:url" -pm \\\n       | nuclei -silent -severity high,critical',
        '# WHOIS lookup on every discovered subdomain',
        'python simplerecon.py -d target.com --no-banner \\\n       | strx -st "echo {STRING}" -module "clc:whois" -pm',
        '# notify Telegram channel with every new live subdomain',
        'python simplerecon.py -d target.com --verify-live --no-banner \\\n       | strx -st "echo {STRING}" -module "con:telegram" -pm',
        '# combine: dns -> port scan via nmap module -> save report',
        'python simplerecon.py -d target.com --no-banner \\\n       | strx -st "echo {STRING}" -module "clc:dns|ext:ip" -pm \\\n       | strx -st "echo {STRING}" -module "out:csv" -pm',
    ]),
]


def print_examples() -> None:
    import core.colors as C

    print(f'\n{C.bold(C.white("SimpleReconSubdomain — Usage Examples"))}\n')
    for section, cmds in _EXAMPLES:
        print(f'{C.bold(C.cyan("# " + section))}')
        for cmd in cmds:
            if cmd.startswith('#'):
                # inline comment line inside a section
                print(f'  {C.yellow(cmd)}')
            else:
                print(f'  {C.gray(cmd)}')
        print()
