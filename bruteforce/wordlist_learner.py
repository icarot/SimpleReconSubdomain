"""
Wordlist learner — derives DNS brute-force candidates from already-discovered
subdomain names.

Unlike mutation.json (a static word list), this module analyses the patterns
*inside* the discovered names and generates targeted candidates:

  Numeric sequences : api1, api2   → api3 … api9
  Environment fams  : dev-api      → staging-api, qa-api, prod-api
  Geo variants      : cdn-us, cdn-eu → cdn-br, cdn-uk, cdn-de …
  Version bumps     : v2 found     → v1, v3
  Token combos      : {dev,api,eu} → missing cross-product entries

Returns a set of *label* strings (not FQDNs).  The caller is responsible for
converting them to full subdomain candidates: f'{label}.{domain}'.
"""
from __future__ import annotations

import itertools
import re

_ENVS = [
    'dev', 'develop', 'development',
    'staging', 'stage',
    'qa', 'uat',
    'prod', 'production',
    'test', 'testing',
    'sandbox', 'preprod', 'demo', 'preview',
]

_GEO = [
    'us', 'eu', 'br', 'uk', 'de', 'fr',
    'jp', 'sg', 'au', 'ap', 'sa', 'ca',
    'us-east', 'us-west', 'eu-west', 'ap-southeast',
]

_SEPS = ('-', '.', '')   # separators to try when combining tokens

_RE_NUM_SUFFIX = re.compile(r'^(.*?)(\d+)$')
_RE_VERSION    = re.compile(r'v(\d+)', re.IGNORECASE)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_labels(subdomains: set[str], domain: str) -> set[str]:
    """Strip '.domain' suffix from each subdomain and return bare labels."""
    suffix = f'.{domain}'
    labels: set[str] = set()
    for sub in subdomains:
        sub = sub.lower().strip()
        if sub.endswith(suffix):
            label = sub[: -len(suffix)]
            if label:
                labels.add(label)
        elif sub == domain:
            pass
    return labels


def _tokenise(label: str) -> list[str]:
    """Split a label on common separators into constituent tokens."""
    parts = re.split(r'[-._]', label)
    return [p for p in parts if p]


# ── Pattern extractors ────────────────────────────────────────────────────────

def _numeric_sequences(labels: set[str]) -> set[str]:
    """api1, api2 → api3 … api9  (fills gaps and extends runs)."""
    candidates: set[str] = set()
    # Group by prefix
    groups: dict[str, list[int]] = {}
    for label in labels:
        m = _RE_NUM_SUFFIX.match(label)
        if m:
            prefix, num_str = m.group(1), m.group(2)
            groups.setdefault(prefix, []).append(int(num_str))

    for prefix, nums in groups.items():
        if not prefix:
            continue
        lo, hi = min(nums), max(nums)
        # Generate the expected sequence + one step beyond
        for n in range(max(1, lo - 1), hi + 3):
            candidate = f'{prefix}{n}'
            if candidate not in labels:
                candidates.add(candidate)

    return candidates


def _env_families(labels: set[str]) -> set[str]:
    """dev-api → staging-api, qa-api, prod-api."""
    candidates: set[str] = set()

    for label in labels:
        tokens = _tokenise(label)
        if not tokens:
            continue

        # Detect if any token is an environment word
        env_found: list[str] = [t for t in tokens if t in _ENVS]
        if not env_found:
            continue

        # For each env token found, substitute with all other envs
        for env_tok in env_found:
            remainder = [t for t in tokens if t != env_tok]
            if not remainder:
                continue
            sep = '-' if '-' in label else ('.' if '.' in label else '-')
            for other_env in _ENVS:
                if other_env == env_tok:
                    continue
                # Try env as prefix and suffix
                candidate_prefix = other_env + sep + sep.join(remainder)
                candidate_suffix = sep.join(remainder) + sep + other_env
                for c in (candidate_prefix, candidate_suffix):
                    if c not in labels:
                        candidates.add(c)

    return candidates


def _geo_variants(labels: set[str]) -> set[str]:
    """cdn-us, cdn-eu → cdn-br, cdn-uk, cdn-de …"""
    candidates: set[str] = set()

    for label in labels:
        tokens = _tokenise(label)
        geo_found = [t for t in tokens if t in _GEO]
        if not geo_found:
            continue

        sep = '-' if '-' in label else ('.' if '.' in label else '-')
        for geo_tok in geo_found:
            base_tokens = [t for t in tokens if t != geo_tok]
            if not base_tokens:
                continue
            base = sep.join(base_tokens)
            for other_geo in _GEO:
                if other_geo == geo_tok:
                    continue
                for c in (f'{base}{sep}{other_geo}', f'{other_geo}{sep}{base}'):
                    if c not in labels:
                        candidates.add(c)

    return candidates


def _version_bumps(labels: set[str]) -> set[str]:
    """v2 found in labels → generate v1, v3."""
    candidates: set[str] = set()

    for label in labels:
        for m in _RE_VERSION.finditer(label):
            ver = int(m.group(1))
            for delta in (-1, 1, 2):
                new_ver = ver + delta
                if new_ver < 1:
                    continue
                new_label = label[: m.start(1)] + str(new_ver) + label[m.end(1):]
                if new_label not in labels:
                    candidates.add(new_label)

    return candidates


def _token_combinations(labels: set[str]) -> set[str]:
    """
    Extract atomic tokens from all labels and generate missing combinations.

    Limits: only combine 2-token pairs, only with '-' separator, only when
    both tokens appear in at least 2 different labels (reduces noise).
    """
    candidates: set[str] = set()

    # Count how many labels each token appears in
    token_freq: dict[str, int] = {}
    for label in labels:
        for tok in set(_tokenise(label)):
            token_freq[tok] = token_freq.get(tok, 0) + 1

    # Tokens that appear in ≥2 labels are "established" vocabulary
    vocab = {t for t, c in token_freq.items() if c >= 2 and len(t) >= 2}
    if len(vocab) < 2:
        return candidates

    for a, b in itertools.combinations(sorted(vocab), 2):
        for c in (f'{a}-{b}', f'{b}-{a}'):
            if c not in labels:
                candidates.add(c)

    return candidates


# ── Public API ────────────────────────────────────────────────────────────────

def learn(subdomains: set[str], domain: str) -> set[str]:
    """
    Analyse *subdomains* and return new label candidates for DNS brute-force.

    Args:
        subdomains: Full subdomain FQDNs as returned by Engine (e.g. 'api.example.com').
        domain:     The target domain (e.g. 'example.com').

    Returns:
        Set of label strings (bare prefixes, not FQDNs) not already in the
        discovered set.  The caller converts them: f'{label}.{domain}'.
    """
    labels = _extract_labels(subdomains, domain)
    if not labels:
        return set()

    candidates: set[str] = set()
    candidates |= _numeric_sequences(labels)
    candidates |= _env_families(labels)
    candidates |= _geo_variants(labels)
    candidates |= _version_bumps(labels)
    candidates |= _token_combinations(labels)

    # Remove what was already discovered + empty strings
    candidates -= labels
    candidates.discard('')

    return candidates
