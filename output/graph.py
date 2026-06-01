"""
Network graph builder.

Converts a per-target result dict (as produced by Engine.run_target()) into a
node/edge structure suitable for graph visualization (vis-network, cytoscape,
gephi, etc.).

Pure function — no I/O, no global state.
"""
from __future__ import annotations


_STATUS_COLORS = {
    '2xx': '#4caf50',  # green
    '3xx': '#ff9800',  # orange
    '4xx': '#f44336',  # red
    '5xx': '#9c27b0',  # purple
    'none': '#9e9e9e', # gray (unreachable / not probed)
}

_TYPE_COLORS = {
    'domain':      '#1976d2',  # blue
    'subdomain':   '#9e9e9e',  # gray default (overridden by status)
    'ip':          '#00897b',  # teal
    'cloud':       '#fbc02d',  # yellow
    'cname':       '#7b1fa2',  # purple
    'tld_variant': '#e91e63',  # pink
}


def _status_color(status) -> str:
    if status is None:
        return _STATUS_COLORS['none']
    try:
        s = int(status)
    except (TypeError, ValueError):
        return _STATUS_COLORS['none']
    if 200 <= s < 300:
        return _STATUS_COLORS['2xx']
    if 300 <= s < 400:
        return _STATUS_COLORS['3xx']
    if 400 <= s < 500:
        return _STATUS_COLORS['4xx']
    if 500 <= s < 600:
        return _STATUS_COLORS['5xx']
    return _STATUS_COLORS['none']


def _is_external(host: str, domain: str) -> bool:
    if not host:
        return False
    h = host.strip().lower().rstrip('.')
    if not h or h == domain:
        return False
    return not h.endswith(f'.{domain}')


def build_network_graph(result: dict) -> dict:
    """
    Build a network graph from a per-target result dict.

    Returns:
        {
          'nodes': [{'id', 'label', 'type', 'color', ...}, ...],
          'edges': [{'from', 'to', 'relation'}, ...],
          'stats': {'domains', 'subdomains', 'ips', 'clouds',
                    'cnames', 'tld_variants', 'edges'},
        }
    """
    domain: str = result.get('domain', '')
    subdomains: set = result.get('subdomains', set()) or set()
    live: dict = result.get('live', {}) or {}
    tld_variants: set = result.get('tld_variants', set()) or set()

    nodes: list[dict] = []
    edges: list[dict] = []
    seen_ids: set[str] = set()

    def add_node(node_id: str, **attrs) -> None:
        if not node_id or node_id in seen_ids:
            return
        seen_ids.add(node_id)
        attrs['id'] = node_id
        nodes.append(attrs)

    def add_edge(src: str, dst: str, relation: str) -> None:
        if not src or not dst or src == dst:
            return
        edges.append({'from': src, 'to': dst, 'relation': relation})

    # ── Root domain node ─────────────────────────────────────────────
    add_node(
        domain,
        label=domain,
        type='domain',
        color=_TYPE_COLORS['domain'],
        group=domain,
    )

    # ── Subdomain nodes + has_subdomain edges ────────────────────────
    for sub in sorted(subdomains):
        info = live.get(sub, {}) or {}
        status = info.get('status')
        label = sub[: -len(domain) - 1] if sub.endswith(f'.{domain}') else sub
        add_node(
            sub,
            label=label or sub,
            type='subdomain',
            color=_status_color(status),
            status=status,
            title=info.get('title', '') or '',
            server=info.get('server', '') or '',
            group=domain,
        )
        add_edge(domain, sub, 'has_subdomain')

        # IPs
        for ip in info.get('ips', []) or []:
            add_node(ip, label=ip, type='ip', color=_TYPE_COLORS['ip'])
            add_edge(sub, ip, 'resolves_to')

        # Cloud provider (one node per provider, reused across subdomains)
        cloud = info.get('cloud')
        if cloud:
            cid = f'cloud:{cloud}'
            add_node(cid, label=cloud.upper(), type='cloud',
                     color=_TYPE_COLORS['cloud'])
            add_edge(sub, cid, 'hosted_on')

        # CNAME — only when external to the target
        cname = info.get('cname')
        if cname and _is_external(cname, domain):
            cid = f'cname:{cname}'
            add_node(cid, label=cname, type='cname',
                     color=_TYPE_COLORS['cname'])
            add_edge(sub, cid, 'cname_to')

    # ── TLD variants ─────────────────────────────────────────────────
    for variant in sorted(tld_variants):
        vid = f'tld:{variant}'
        add_node(vid, label=variant, type='tld_variant',
                 color=_TYPE_COLORS['tld_variant'])
        add_edge(vid, domain, 'tld_variant_of')

    # ── Stats ────────────────────────────────────────────────────────
    counts: dict = {
        'domains': 0, 'subdomains': 0, 'ips': 0,
        'clouds': 0, 'cnames': 0, 'tld_variants': 0,
    }
    for n in nodes:
        t = n.get('type', '')
        key = {
            'domain': 'domains',
            'subdomain': 'subdomains',
            'ip': 'ips',
            'cloud': 'clouds',
            'cname': 'cnames',
            'tld_variant': 'tld_variants',
        }.get(t)
        if key:
            counts[key] += 1
    counts['edges'] = len(edges)

    return {'nodes': nodes, 'edges': edges, 'stats': counts}


def merge_graphs(graphs: list[dict]) -> dict:
    """Combine multiple per-target graphs into a single graph (dedup nodes)."""
    nodes_by_id: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple] = set()

    for g in graphs:
        for n in g.get('nodes', []):
            nid = n.get('id')
            if nid and nid not in nodes_by_id:
                nodes_by_id[nid] = n
        for e in g.get('edges', []):
            key = (e.get('from'), e.get('to'), e.get('relation'))
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append(e)

    merged_nodes = list(nodes_by_id.values())
    counts: dict = {
        'domains': 0, 'subdomains': 0, 'ips': 0,
        'clouds': 0, 'cnames': 0, 'tld_variants': 0,
    }
    for n in merged_nodes:
        t = n.get('type', '')
        key = {
            'domain': 'domains',
            'subdomain': 'subdomains',
            'ip': 'ips',
            'cloud': 'clouds',
            'cname': 'cnames',
            'tld_variant': 'tld_variants',
        }.get(t)
        if key:
            counts[key] += 1
    counts['edges'] = len(edges)

    return {'nodes': merged_nodes, 'edges': edges, 'stats': counts}
