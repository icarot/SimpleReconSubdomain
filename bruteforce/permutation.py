import json
from pathlib import Path

_MUTATION_FILE = Path(__file__).parent.parent / 'config' / 'mutation.json'

MUTATIONS: list[str] = json.loads(_MUTATION_FILE.read_text())['mutations']


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
