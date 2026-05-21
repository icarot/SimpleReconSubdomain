import argparse

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
