"""ANSI color helpers.

Call ``init(no_color)`` once at program startup before any output.
Colors are automatically disabled when stdout is not a TTY (piped output)
or when the NO_COLOR environment variable is set (https://no-color.org/).
"""

from __future__ import annotations

import os
import re
import sys

_enabled: bool = True


def init(no_color: bool = False) -> None:
    """Configure the color system. Must be called before any output."""
    global _enabled
    if no_color:
        _enabled = False
        return
    # Respect NO_COLOR env var and dumb terminals
    if os.getenv('NO_COLOR') is not None or os.getenv('TERM') == 'dumb':
        _enabled = False
        return
    # Disable when stdout is not a TTY (e.g. piped to file/grep)
    if not (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()):
        _enabled = False


def _c(code: str, text: str) -> str:
    if not _enabled:
        return text
    return f'\033[{code}m{text}\033[0m'


def bold(text: str)   -> str: return _c('1',  text)
def dim(text: str)    -> str: return _c('2',  text)
def gray(text: str)   -> str: return _c('90', text)
def red(text: str)    -> str: return _c('91', text)
def green(text: str)  -> str: return _c('92', text)
def yellow(text: str) -> str: return _c('93', text)
def blue(text: str)   -> str: return _c('94', text)
def cyan(text: str)   -> str: return _c('96', text)
def white(text: str)  -> str: return _c('97', text)


_SEP_RE = re.compile(r'^-{10,}$')


def format_msg(msg: str) -> str:
    """Apply contextual colors to a log message based on its prefix tokens."""
    if not _enabled:
        return msg

    stripped = msg.strip()

    # Separator lines (e.g. '----...----') → gray
    if _SEP_RE.match(stripped):
        return gray(msg)

    # Colorize standard prefix tokens (order matters: do before generic [word] rule)
    if '[+]' in msg:
        msg = msg.replace('[+]', green('[+]'), 1)
    if '[*]' in msg:
        msg = msg.replace('[*]', blue('[*]'), 1)
    if '[!]' in msg:
        msg = msg.replace('[!]', yellow('[!]'), 1)

    # Colorize source/module names in brackets: [crtsh], [virustotal], etc.
    # \w matches only alphanumeric + underscore, so [+] / [*] / [!] are not affected
    msg = re.sub(r'\[(\w+)\]', lambda m: f'[{cyan(m.group(1))}]', msg)

    return msg
