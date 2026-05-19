import csv
import io
import json
import sys
from datetime import datetime
from typing import Optional

import core.colors as colors


def save_output(
    results: list[dict],
    fmt: str = 'txt',
    outfile: Optional[str] = None,
    quiet: bool = False,
) -> None:
    """
    Serialize *results* to the requested format and write to *outfile* or stdout.

    *results* is a list of per-domain dicts with keys:
        domain, subdomains (set), live (dict), sources (dict)
    """
    segments: list[str] = []

    for result in results:
        domain = result['domain']
        subdomains: set[str] = result.get('subdomains', set())
        live: dict = result.get('live', {})
        sources: dict = result.get('sources', {})
        timestamp = datetime.now().isoformat()

        if fmt == 'json':
            data = {
                'domain': domain,
                'timestamp': timestamp,
                'total': len(subdomains),
                'subdomains': sorted(subdomains),
                'live_hosts': {
                    sub: info
                    for sub, info in live.items()
                    if info.get('status') is not None
                },
                'sources': sources,
            }
            segments.append(json.dumps(data, indent=2))

        elif fmt == 'csv':
            buf = io.StringIO()
            writer = csv.DictWriter(
                buf,
                fieldnames=['domain', 'subdomain', 'status', 'title', 'server'],
            )
            writer.writeheader()
            for sub in sorted(subdomains):
                live_info = live.get(sub, {})
                writer.writerow({
                    'domain': domain,
                    'subdomain': sub,
                    'status': live_info.get('status', ''),
                    'title': live_info.get('title', ''),
                    'server': live_info.get('server', ''),
                })
            segments.append(buf.getvalue())

        else:  # txt (default)
            segments.append('\n'.join(sorted(subdomains)))

    output = '\n'.join(segments)

    if outfile:
        try:
            with open(outfile, 'w') as fh:
                fh.write(output)
            if not quiet:
                print(colors.format_msg(f'\n[+] Output saved to: {outfile}'))
        except OSError as exc:
            print(colors.format_msg(f'[!] Could not write to {outfile}: {exc}'), file=sys.stderr)
    else:
        if output:
            print('\n' + output)
