#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SimpleReconSubdomain v2
# https://github.com/MrCl0wnLab/SimpleReconSubdomain
#
# WARNING
# +------------------------------------------------------------------------------+
# |  [!] Legal disclaimer: Usage of SimpleReconSubdomain for attacking           |
# |  targets without prior mutual consent is illegal.                            |
# |  It is the end user's responsibility to obey all applicable                  |
# |  local, state and federal laws.                                              |
# |  Developers assume no liability and are not responsible for any misuse or    |
# |  damage caused by this program.                                              |
# +------------------------------------------------------------------------------+

import asyncio
import sys

from cli.parser import build_parser, print_sources
from core.engine import Engine
import core.colors as colors

BANNER_SIMPLE = rf"""
                                                 
                 ▄▄▄▄▄▄▄                    ▄▄       ▄▄▄▄▄▄▄                           
                █████▀▀▀ ▀▀                 ██       ███▀▀███▄                       
                 ▀████▄  ██  ███▄███▄ ████▄ ██ ▄█▀█▄ ███▄▄███▀ ▄█▀█▄ ▄████ ▄███▄ ████▄ 
                   ▀████ ██  ██ ██ ██ ██ ██ ██ ██▄█▀ ███▀▀██▄  ██▄█▀ ██    ██ ██ ██ ██ 
                ███████▀ ██▄ ██ ██ ██ ████▀ ██ ▀█▄▄▄ ███  ▀███ ▀█▄▄▄ ▀████ ▀███▀ ██ ██ v2   
                                      ██"""
BANNER_SUB = rf"""                                                                                 
        ░██████             ██        ░███████                                         ░██           
     ░██   ░██             ░██        ░██   ░██                                                      
    ░██         ░██    ░██ ░████████  ░██    ░██  ░███████  ░█████████████   ░██████   ░██░████████  
     ░████████  ░██    ░██ ░██    ░██ ░██    ░██ ░██    ░██ ░██   ░██   ░██       ░██  ░██░██    ░██ 
            ░██ ░██    ░██ ░██    ░██ ░██    ░██ ░██    ░██ ░██   ░██   ░██  ░███████  ░██░██    ░██ 
     ░██   ░██  ░██   ░███ ░███   ░██ ░██   ░██  ░██    ░██ ░██   ░██   ░██ ░██   ░██  ░██░██    ░██ 
      ░██████    ░█████░██ ░██░█████  ░███████    ░███████  ░██   ░██   ░██  ░█████░██ ░██░██    ░██                        
"""
BANNER_BUTTON = rf"""                                                                                             
                                                        {colors.bold('By: MrCl0wn')} {colors.white(f"/ https://blog.mrcl0wn.com")}
                                                                      {colors.white("https://twitter.com/MrCl0wnLab")}
                                                                      {colors.white("https://github.com/MrCl0wnLab")}
"""

BANNER = colors.red(BANNER_SIMPLE) + colors.cyan(BANNER_SUB) + colors.white(BANNER_BUTTON)


def main() -> None:
    # Pre-initialize colors before building the parser so --help output is colored.
    # Check sys.argv directly since args are not parsed yet.
    colors.init(no_color='--no-color' in sys.argv)

    parser = build_parser()
    args = parser.parse_args()

    if args.list_sources:
        print_sources()
        sys.exit(0)

    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)

    # --no-banner implies quiet mode: suppress banner + all process messages
    if getattr(args, 'no_banner', False):
        args.quiet = True

    if not args.quiet:
        print(colors.cyan(BANNER))

    engine = Engine(args)
    try:
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        print('\n' + colors.format_msg('[!] Interrupted by user.'))
        sys.exit(0)


if __name__ == '__main__':
    main()
