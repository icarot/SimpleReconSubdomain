"""
Markdown report renderer for SimpleReconSubdomain.

Converts the list of per-target result dicts (produced by Engine.run_target())
into a human-readable Markdown document suitable for delivering to clients,
pasting into GitHub issues/PRs, or viewing in any Markdown renderer.

Pure function — no I/O, no global state.
"""
from __future__ import annotations

from datetime import datetime


# ── Section builders ──────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    """Escape pipe characters inside table cells."""
    return str(s).replace('|', '\\|')


def _status_badge(status) -> str:
    if status is None:
        return '—'
    try:
        s = int(status)
    except (TypeError, ValueError):
        return str(status)
    if 200 <= s < 300:
        return f'`{s}` ✅'
    if 300 <= s < 400:
        return f'`{s}` ↪'
    if 400 <= s < 500:
        return f'`{s}` ⚠'
    if 500 <= s < 600:
        return f'`{s}` 🔴'
    return f'`{s}`'


def _header(domain: str, sources: dict, subdomains: set, live: dict) -> str:
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    source_list = ', '.join(f'`{s}`' for s in sorted(sources)) if sources else '—'
    live_count = sum(1 for i in live.values() if i.get('status') is not None)
    return (
        f'# Reconnaissance Report — {domain}\n\n'
        f'**Date:** {ts}  \n'
        f'**Sources:** {source_list}  \n'
        f'**Subdomains discovered:** {len(subdomains)}  \n'
        f'**Live hosts:** {live_count} / {len(subdomains)}'
    )


def _summary_table(subdomains: set, live: dict, tld_variants: set) -> str:
    statuses = [i.get('status') for i in live.values()]
    c_2xx = sum(1 for s in statuses if s is not None and 200 <= s < 300)
    c_3xx = sum(1 for s in statuses if s is not None and 300 <= s < 400)
    c_4xx = sum(1 for s in statuses if s is not None and 400 <= s < 500)
    c_5xx = sum(1 for s in statuses if s is not None and 500 <= s < 600)
    c_dead = sum(1 for s in statuses if s is None)
    takeovers = sum(1 for i in live.values() if i.get('takeover'))
    wafs = sum(1 for i in live.values() if i.get('waf'))

    # Cloud distribution
    cloud_counts: dict[str, int] = {}
    for info in live.values():
        c = info.get('cloud')
        if c:
            cloud_counts[c] = cloud_counts.get(c, 0) + 1
    cloud_str = ', '.join(
        f'{k.capitalize()} ({v})'
        for k, v in sorted(cloud_counts.items(), key=lambda x: -x[1])
    ) or '—'

    rows = [
        ('Subdomains discovered', len(subdomains)),
        ('Live — 2xx',  c_2xx),
        ('Redirects — 3xx', c_3xx),
        ('Client errors — 4xx', c_4xx),
        ('Server errors — 5xx', c_5xx),
        ('Unreachable', c_dead),
        ('Takeover candidates', f'**{takeovers}**' if takeovers else 0),
        ('WAF-protected hosts', wafs),
        ('Cloud providers', cloud_str),
        ('TLD variants', len(tld_variants)),
    ]

    lines = ['## Summary', '', '| Metric | Value |', '|--------|-------|']
    for label, value in rows:
        lines.append(f'| {label} | {value} |')
    return '\n'.join(lines)


def _takeover_section(live: dict) -> str:
    takeovers = {s: i for s, i in live.items() if i.get('takeover')}
    if not takeovers:
        return ''
    lines = [
        '## ⚠ Takeover Candidates', '',
        '| Subdomain | Status | CNAME | Service |',
        '|-----------|--------|-------|---------|',
    ]
    for sub, info in sorted(takeovers.items()):
        cname   = _esc(info.get('cname') or '—')
        service = _esc(info.get('takeover') or '—')
        status  = _status_badge(info.get('status'))
        lines.append(f'| `{_esc(sub)}` | {status} | `{cname}` | {service} |')
    return '\n'.join(lines)


def _live_hosts_table(live: dict) -> str:
    live_hosts = {s: i for s, i in live.items() if i.get('status') is not None}
    if not live_hosts:
        return '## Live Hosts\n\n*No live hosts found.*'

    lines = [
        '## Live Hosts', '',
        '| Subdomain | Status | Title | Server | Cloud | WAF | ms |',
        '|-----------|--------|-------|--------|-------|-----|----|',
    ]
    for sub in sorted(live_hosts):
        info   = live_hosts[sub]
        status = _status_badge(info.get('status'))
        title  = _esc((info.get('title') or '')[:50])
        server = _esc((info.get('server') or '—')[:30])
        cloud  = info.get('cloud') or '—'
        waf    = info.get('waf') or '—'
        ms     = info.get('response_ms')
        ms_str = f'{ms}' if ms is not None else '—'
        lines.append(
            f'| `{_esc(sub)}` | {status} | {title} | {server} | {cloud} | {waf} | {ms_str} |'
        )
    return '\n'.join(lines)


def _duplicate_bodies_section(duplicate_bodies: dict) -> str:
    if not duplicate_bodies:
        return ''
    lines = [
        '## Duplicate Body Hashes',
        '',
        '*Hosts sharing identical response bodies — possible wildcard DNS or CDN farm.*',
        '',
        '| Hash | Subdomains |',
        '|------|-----------|',
    ]
    for h, subs in sorted(duplicate_bodies.items()):
        subs_str = ', '.join(f'`{_esc(s)}`' for s in subs)
        lines.append(f'| `{h}` | {subs_str} |')
    return '\n'.join(lines)


def _all_subdomains_section(subdomains: set) -> str:
    if not subdomains:
        return ''
    lines = ['## All Subdomains', '', '```']
    lines.extend(sorted(subdomains))
    lines.append('```')
    return '\n'.join(lines)


def _tld_section(tld_variants: set) -> str:
    if not tld_variants:
        return ''
    lines = [
        '## TLD Variants', '',
        '| Domain |',
        '|--------|',
    ]
    for v in sorted(tld_variants):
        lines.append(f'| `{_esc(v)}` |')
    return '\n'.join(lines)


def _extras_section(extras: dict) -> str:
    hosts = sorted(extras.get('hosts', set()))
    ips   = sorted(extras.get('ips', set()))
    urls  = sorted(extras.get('urls', set()))
    if not (hosts or ips or urls):
        return ''

    lines = ['## Extras', '']
    if hosts:
        lines += ['### External Hosts', '', '```']
        lines += hosts
        lines += ['```', '']
    if ips:
        lines += ['### IPs', '', '```']
        lines += ips
        lines += ['```', '']
    if urls:
        lines += ['### Crawled URLs', '', '```']
        lines += urls[:50]  # cap to avoid enormous reports
        if len(urls) > 50:
            lines.append(f'… and {len(urls) - 50} more')
        lines.append('```')
    return '\n'.join(lines)


def _sources_section(sources: dict) -> str:
    if not sources:
        return ''
    lines = [
        '## Source Contributions', '',
        '| Source | Subdomains |',
        '|--------|-----------|',
    ]
    for src, count in sorted(sources.items(), key=lambda x: -x[1]):
        lines.append(f'| `{src}` | {count} |')
    return '\n'.join(lines)


# ── Public API ────────────────────────────────────────────────────────────────

def render_markdown(results: list[dict]) -> str:
    """
    Render a Markdown reconnaissance report from a list of Engine result dicts.

    Returns the full report as a single string.
    """
    sections: list[str] = []

    for result in results:
        domain         = result.get('domain', '')
        subdomains     = result.get('subdomains', set()) or set()
        live           = result.get('live', {}) or {}
        sources        = result.get('sources', {}) or {}
        tld_variants   = result.get('tld_variants', set()) or set()
        extras         = result.get('extras', {}) or {}
        dup_bodies     = result.get('duplicate_bodies', {}) or {}

        sections.append(_header(domain, sources, subdomains, live))
        sections.append(_summary_table(subdomains, live, tld_variants))

        takeover_sec = _takeover_section(live)
        if takeover_sec:
            sections.append(takeover_sec)

        sections.append(_live_hosts_table(live))

        dup_sec = _duplicate_bodies_section(dup_bodies)
        if dup_sec:
            sections.append(dup_sec)

        sections.append(_all_subdomains_section(subdomains))

        tld_sec = _tld_section(tld_variants)
        if tld_sec:
            sections.append(tld_sec)

        extras_sec = _extras_section(extras)
        if extras_sec:
            sections.append(extras_sec)

        src_sec = _sources_section(sources)
        if src_sec:
            sections.append(src_sec)

        sections.append('---\n\n*Generated by [SimpleReconSubdomain v2](https://github.com/MrCl0wnLab/SimpleReconSubdomain)*')

    return '\n\n---\n\n'.join(sections)
