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
        domain, subdomains (set), live (dict), sources (dict),
        tld_variants (set, optional)

    Formats: txt, json, csv, ndjson
    """
    segments: list[str] = []

    for result in results:
        domain = result['domain']
        subdomains: set[str] = result.get('subdomains', set())
        live: dict = result.get('live', {})
        sources: dict = result.get('sources', {})
        tld_variants: set[str] = result.get('tld_variants', set())
        extras: dict = result.get('extras', {})
        extra_hosts: set[str] = extras.get('hosts', set())
        extra_ips: set[str]   = extras.get('ips', set())
        extra_urls: set[str]  = extras.get('urls', set())
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
                    if info.get('ips'):
                        entry['ips'] = info['ips']
                    if info.get('cloud'):
                        entry['cloud'] = info['cloud']
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
            if tld_variants:
                data['tld_variants'] = sorted(tld_variants)
            if extra_hosts or extra_ips or extra_urls:
                data['extras'] = {}
                if extra_hosts:
                    data['extras']['hosts'] = sorted(extra_hosts)
                if extra_ips:
                    data['extras']['ips'] = sorted(extra_ips)
                if extra_urls:
                    data['extras']['urls'] = sorted(extra_urls)
            segments.append(json.dumps(data, indent=2))

        elif fmt == 'csv':
            buf = io.StringIO()
            writer = csv.DictWriter(
                buf,
                fieldnames=[
                    'domain', 'subdomain', 'type',
                    'status', 'title', 'server',
                    'ips', 'cloud',
                    'tls_sans', 'takeover', 'cname', 'waf',
                ],
            )
            writer.writeheader()
            for sub in sorted(subdomains):
                live_info = live.get(sub, {})
                sans = live_info.get('tls_sans', [])
                ips = live_info.get('ips', [])
                writer.writerow({
                    'domain': domain,
                    'subdomain': sub,
                    'type': 'subdomain',
                    'status': live_info.get('status', ''),
                    'title': live_info.get('title', ''),
                    'server': live_info.get('server', ''),
                    'ips': '|'.join(ips) if ips else '',
                    'cloud': live_info.get('cloud', ''),
                    'tls_sans': '|'.join(sans) if sans else '',
                    'takeover': live_info.get('takeover', ''),
                    'cname': live_info.get('cname', ''),
                    'waf': live_info.get('waf', ''),
                })
            for variant in sorted(tld_variants):
                writer.writerow({
                    'domain': domain,
                    'subdomain': variant,
                    'type': 'tld_variant',
                    'status': '', 'title': '', 'server': '',
                    'ips': '', 'cloud': '',
                    'tls_sans': '', 'takeover': '', 'cname': '', 'waf': '',
                })
            for host in sorted(extra_hosts):
                writer.writerow({
                    'domain': domain, 'subdomain': host, 'type': 'extra_host',
                    'status': '', 'title': '', 'server': '',
                    'ips': '', 'cloud': '', 'tls_sans': '', 'takeover': '', 'cname': '', 'waf': '',
                })
            for ip in sorted(extra_ips):
                writer.writerow({
                    'domain': domain, 'subdomain': ip, 'type': 'extra_ip',
                    'status': '', 'title': '', 'server': '',
                    'ips': '', 'cloud': '', 'tls_sans': '', 'takeover': '', 'cname': '', 'waf': '',
                })
            for url in sorted(extra_urls):
                writer.writerow({
                    'domain': domain, 'subdomain': url, 'type': 'extra_url',
                    'status': '', 'title': '', 'server': '',
                    'ips': '', 'cloud': '', 'tls_sans': '', 'takeover': '', 'cname': '', 'waf': '',
                })
            segments.append(buf.getvalue())

        elif fmt == 'ndjson':
            # One compact JSON line per subdomain — pipe-friendly
            for sub in sorted(subdomains):
                live_info = live.get(sub, {})
                record: dict = {'domain': domain, 'subdomain': sub, 'type': 'subdomain'}
                if live_info.get('status') is not None:
                    record['status'] = live_info['status']
                    if live_info.get('title'):
                        record['title'] = live_info['title']
                    if live_info.get('server'):
                        record['server'] = live_info['server']
                    if live_info.get('ips'):
                        record['ips'] = live_info['ips']
                    if live_info.get('cloud'):
                        record['cloud'] = live_info['cloud']
                    if live_info.get('tls_sans'):
                        record['tls_sans'] = live_info['tls_sans']
                    if live_info.get('takeover'):
                        record['takeover'] = live_info['takeover']
                    if live_info.get('cname'):
                        record['cname'] = live_info['cname']
                    if live_info.get('waf'):
                        record['waf'] = live_info['waf']
                segments.append(json.dumps(record))
            for variant in sorted(tld_variants):
                segments.append(json.dumps({
                    'domain': domain, 'subdomain': variant, 'type': 'tld_variant'
                }))
            for host in sorted(extra_hosts):
                segments.append(json.dumps({'domain': domain, 'subdomain': host, 'type': 'extra_host'}))
            for ip in sorted(extra_ips):
                segments.append(json.dumps({'domain': domain, 'subdomain': ip, 'type': 'extra_ip'}))
            for url in sorted(extra_urls):
                segments.append(json.dumps({'domain': domain, 'subdomain': url, 'type': 'extra_url'}))

        else:  # txt (default)
            lines = list(sorted(subdomains))
            if tld_variants:
                if not quiet:
                    lines.append('')
                    lines.append('# TLD variants')
                lines.extend(sorted(tld_variants))
            if extra_hosts:
                if not quiet:
                    lines.append('')
                    lines.append('# External hosts')
                lines.extend(sorted(extra_hosts))
            if extra_ips:
                if not quiet:
                    lines.append('')
                    lines.append('# IPs')
                lines.extend(sorted(extra_ips))
            if extra_urls:
                if not quiet:
                    lines.append('')
                    lines.append('# URLs')
                lines.extend(sorted(extra_urls))
            segments.append('\n'.join(lines))

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
