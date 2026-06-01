"""
Run-config preset system for SimpleReconSubdomain.

A run-config is a JSON file that stores CLI argument defaults, enabling
repeatable scans without long command lines.

Usage:
    python simplerecon.py -d target.com --config config/run_config.example.json

Precedence (highest → lowest):
    1. Explicit CLI flags     (always win)
    2. Run-config file values (applied where CLI kept the argparse default)
    3. Argparse defaults      (built into parser)

Only keys present in the JSON and not None are applied; unknown keys are
silently ignored so configs stay forward/backward compatible.
"""
from __future__ import annotations

import json
import os
from argparse import Namespace

# Argparse defaults — used to detect whether the user explicitly supplied a flag.
# Any value equal to the default is assumed to be "not set by the user".
_PARSER_DEFAULTS: dict[str, object] = {
    'output': 'txt',
    'outfile': None,
    'threads': 8,
    'timeout': 30,
    'rate_limit': 0,
    'profile': None,
    'sources': None,
    'exclude': None,
    'no_passive': False,
    'brute': None,
    'resolvers': None,
    'check_resolvers': False,
    'permute': False,
    'wildcard_tests': 3,
    'validate_resolvers': False,
    'verify_live': False,
    'recursive': False,
    'recursive_depth': 1,
    'tld_brute': None,
    'show_extras': False,
    'proxy': None,
    'user_agent': 'SimpleReconSubdomain/2',
    'verbose': 0,
    'quiet': False,
    'no_banner': False,
    'no_color': False,
    'config': None,
}


def load_run_config(path: str) -> dict:
    """Load and return a run-config JSON as a flat dict.

    Raises SystemExit on file-not-found or JSON parse error so the caller
    gets a clean error message.
    """
    import sys
    import core.colors as colors

    if not os.path.isfile(path):
        print(colors.format_msg(f'[!] [config] Run-config file not found: {path}'))
        sys.exit(1)

    try:
        with open(path, 'r') as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        print(colors.format_msg(f'[!] [config] Invalid JSON in {path}: {exc}'))
        sys.exit(1)

    if not isinstance(data, dict):
        print(colors.format_msg(f'[!] [config] Run-config must be a JSON object: {path}'))
        sys.exit(1)

    return data


def apply_run_config(args: Namespace, config: dict) -> None:
    """Apply config values to *args* only where the arg still holds its default.

    CLI-supplied values (i.e. values that differ from the argparse default)
    are never overwritten.
    """
    for key, value in config.items():
        if value is None:
            continue
        if key not in _PARSER_DEFAULTS:
            continue
        current = getattr(args, key, _PARSER_DEFAULTS[key])
        if current == _PARSER_DEFAULTS[key]:
            setattr(args, key, value)
