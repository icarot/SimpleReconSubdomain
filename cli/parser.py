import argparse

# All source names recognized by the engine
ALL_PASSIVE = [
    'rapiddns', 'jldc', 'crtsh', 'certspotter',
    'urlscan', 'hackertarget', 'wayback', 'robtex',
    'alienvault', 'bufferover',
    'virustotal', 'securitytrails',  # requerem API key (config/api_keys.json)
    'censys', 'shodan',              # requerem API key (config/api_keys.json)
    'grayhatwarfare',                    # API key obrigatória (grayhatwarfare_token)
    'leakix',                        # API key opcional  (leakix_token)
    'fullhunt',                      # API key obrigatória (fullhunt_token)
]

ALL_ACTIVE = ['zone_transfer', 'dns_mining']
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
    _epilog_raw = (
        '\nexamples:\n'
        '  python simplerecon.py -d target.com\n'
        '  python simplerecon.py -l domains.txt\n'
        '  python simplerecon.py -d target.com --brute wordlist.txt --threads 20\n'
        '  python simplerecon.py -d target.com --sources crtsh,hackertarget,wayback\n'
        '  python simplerecon.py -d target.com --output json --outfile result.json\n'
        '  python simplerecon.py -d target.com --verify-live --timeout 10\n'
        '  python simplerecon.py -d target.com --permute\n'
        '  python simplerecon.py --list-sources\n'
    )
    epilog = '\n'.join(
        line.replace('examples:', C.bold(C.cyan('examples:'))) if 'examples:' in line
        else C.gray(line) if line.startswith('  python')
        else line
        for line in _epilog_raw.split('\n')
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

    # Output
    parser.add_argument(
        '-o', '--output',
        choices=['txt', 'json', 'csv'],
        default='txt',
        help='Output format (default: txt)',
    )
    parser.add_argument('--outfile', metavar='FILE', help='Write output to file')

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
        '--sources',
        metavar='SOURCES',
        help=f'Comma-separated sources to use (default: all). Available: {", ".join(ALL_SOURCES)}',
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

    # Brute-force
    parser.add_argument(
        '--brute', metavar='WORDLIST', help='Wordlist path for DNS brute-force'
    )
    parser.add_argument(
        '--resolvers', metavar='FILE', help='File with custom DNS resolver IPs'
    )
    parser.add_argument(
        '--permute',
        action='store_true',
        help='Generate and resolve Altdns-style subdomain permutations',
    )

    # Post-processing
    parser.add_argument(
        '--verify-live',
        action='store_true',
        help='Verify which subdomains respond to HTTP/HTTPS',
    )

    # Verbosity
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
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

    return parser


def print_sources() -> None:
    import core.colors as C

    passive_info = [
        ('rapiddns',        'RapidDNS dataset'),
        ('jldc',            'Anubis / JLDC subdomain DB'),
        ('crtsh',           'Certificate Transparency - crt.sh'),
        ('certspotter',     'Certificate Transparency - CertSpotter'),
        ('urlscan',         'URLScan.io  [API key opcional]'),
        ('hackertarget',    'HackerTarget host search  [API key opcional]'),
        ('wayback',         'Wayback Machine (web.archive.org)'),
        ('robtex',          'Robtex passive DNS'),
        ('alienvault',      'AlienVault OTX  [API key opcional]'),
        ('bufferover',      'BufferOver (Rapid7 FDNS via TLS)'),
        ('virustotal',      'VirusTotal subdomains  [API key obrigatória]'),
        ('securitytrails',  'SecurityTrails DNS history  [API key obrigatória]'),
        ('censys',          'Censys certificate search  [API key obrigatória]'),
        ('shodan',          'Shodan DNS domain  [API key obrigatória]'),
        ('grayhatwarfare',   'GrayHatWarfare cloud buckets  [API key obrigatória]'),
        ('leakix',          'LeakIX cloud/Azure asset index  [API key opcional]'),
        ('fullhunt',        'FullHunt host & subdomain index  [API key obrigatória]'),
    ]
    active_info = [
        ('zone_transfer', 'DNS Zone Transfer (AXFR) - all nameservers'),
        ('dns_mining',    'SPF / DMARC / MX record mining'),
    ]

    def _fmt_desc(desc: str) -> str:
        desc = desc.replace('[API key opcional]',    C.yellow('[API key opcional]'))
        desc = desc.replace('[API key obrigatória]', C.red('[API key obrigatória]'))
        return desc

    print(f'\n{C.bold(C.white("Available sources:"))}\n')
    print(f'  {C.bold(C.cyan("PASSIVE"))} ')  
    for name, desc in passive_info:
        print(f'    {C.cyan(f"{name:<16}")} {_fmt_desc(desc)}')
    print(f'\n  {C.bold(C.cyan("ACTIVE"))} {C.gray("(DNS-based):")}')  
    for name, desc in active_info:
        print(f'    {C.cyan(f"{name:<16}")} {desc}')
    print()
