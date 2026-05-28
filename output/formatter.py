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

    Formats: txt, json, csv, ndjson
    """
    segments: list[str] = []

    for result in results:
        domain = result['domain']
        subdomains: set[str] = result.get('subdomains', set())
        live: dict = result.get('live', {})
        sources: dict = result.get('sources', {})
        timestamp = datetime.now().isoformat()

        if fmt == 'json':
            live_hosts: dict = {}
            for sub, info in live.items():
                if info.get('status') is not None:
                    entry = {
                        'status': info.get('status'),
                        'title': info.get('title', ''),
                        'server': info.get('server', ''),
                        'content_length': info.get('content_length', 0),
                        'url': info.get('url', ''),
                    }
                    sans = info.get('tls_sans', [])
                    if sans:
                        entry['tls_sans'] = sans
                    if info.get('takeover'):
                        entry['takeover'] = info['takeover']
                    if info.get('cname'):
                        entry['cname'] = info['cname']
                    if info.get('waf'):
                        entry['waf'] = info['waf']
                    live_hosts[sub] = entry

            data = {
                'domain': domain,
                'timestamp': timestamp,
                'total': len(subdomains),
                'subdomains': sorted(subdomains),
                'live_hosts': live_hosts,
                'sources': sources,
            }
            segments.append(json.dumps(data, indent=2))

        elif fmt == 'csv':
            buf = io.StringIO()
            writer = csv.DictWriter(
                buf,
                fieldnames=['domain', 'subdomain', 'status', 'title', 'server',
                            'tls_sans', 'takeover', 'cname', 'waf'],
            )
            writer.writeheader()
            for sub in sorted(subdomains):
                live_info = live.get(sub, {})
                sans = live_info.get('tls_sans', [])
                writer.writerow({
                    'domain': domain,
                    'subdomain': sub,
                    'status': live_info.get('status', ''),
                    'title': live_info.get('title', ''),
                    'server': live_info.get('server', ''),
                    'tls_sans': '|'.join(sans) if sans else '',
                    'takeover': live_info.get('takeover', ''),
                    'cname': live_info.get('cname', ''),
                    'waf': live_info.get('waf', ''),
                })
            segments.append(buf.getvalue())

        elif fmt == 'ndjson':
            # One compact JSON line per subdomain — pipe-friendly
            for sub in sorted(subdomains):
                live_info = live.get(sub, {})
                record: dict = {'domain': domain, 'subdomain': sub}
                if live_info.get('status') is not None:
                    record['status'] = live_info['status']
                    if live_info.get('title'):
                        record['title'] = live_info['title']
                    if live_info.get('server'):
                        record['server'] = live_info['server']
                    if live_info.get('tls_sans'):
                        record['tls_sans'] = live_info['tls_sans']
                    if live_info.get('takeover'):
                        record['takeover'] = live_info['takeover']
                    if live_info.get('cname'):
                        record['cname'] = live_info['cname']
                    if live_info.get('waf'):
                        record['waf'] = live_info['waf']
                segments.append(json.dumps(record))

        else:  # txt (default)
            segments.append('\n'.join(sorted(subdomains)))

    output = '\n'.join(segments)

    if outfile:
        try:
            with open(outfile, 'w') as fh:
                fh.write(output)
                if fmt != 'ndjson':
                    fh.write('\n')
            if not quiet:
                print(colors.format_msg(f'\n[+] Output saved to: {outfile}'))
        except OSError as exc:
            print(colors.format_msg(f'[!] Could not write to {outfile}: {exc}'), file=sys.stderr)
    else:
        if output:
            print('\n' + output)
