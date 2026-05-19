MUTATIONS = [
    'dev', 'staging', 'prod', 'test', 'api', 'admin',
    'internal', 'old', 'new', 'v1', 'v2', 'beta',
    'backup', 'corp', 'vpn', 'mail', 'smtp', 'ftp',
    'www', 'app', 'mobile', 'portal', 'login', 'secure',
    'static', 'cdn', 'media', 'img', 'images', 'assets',
]


def generate_permutations(subdomains: set[str], domain: str) -> set[str]:
    """
    Generate Altdns-style permutations from already-discovered subdomains.

    Returns a set of full subdomain strings (e.g. 'dev.api.target.com').
    These are passed directly to the DNS resolver as full hostnames.
    """
    permutations: set[str] = set()

    for sub in subdomains:
        if not sub.endswith(f'.{domain}'):
            continue
        prefix = sub[: -len(f'.{domain}')]
        parts = prefix.split('.')

        for mutation in MUTATIONS:
            # Prepend: dev.api.target.com
            permutations.add(f'{mutation}.{sub}')
            # Suffix on last label: api-dev.target.com
            permutations.add(f'{parts[-1]}-{mutation}.{domain}')
            permutations.add(f'{mutation}-{parts[-1]}.{domain}')
            # Insert after first label: api.dev.target.com
            permutations.add(f'{parts[0]}.{mutation}.{domain}')

    return permutations
