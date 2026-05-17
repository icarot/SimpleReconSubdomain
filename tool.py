# -*- coding: utf-8 -*-
# Autor:    MrCl0wn
# Blog:     https://blog.mrcl0wn.com
# GitHub:   https://github.com/MrCl0wnLab
# Twitter:  https://twitter.com/MrCl0wnLab
# Email:    mrcl0wnlab\@\gmail.com
#
#
# WARNING
# +------------------------------------------------------------------------------+
# |  [!] Legal disclaimer: Usage of SimpleReconSubdomain for attacking           |
# |  targets without prior mutual consent is illegal.                            |
# |  It is the end user's responsibility to obey all applicable                  |
# |  local, state and federal laws.                                              |
# |  Developers assume no liability and are not responsible for any misuse or    |
# |  damage caused by this program                                               |
# +------------------------------------------------------------------------------+

import subprocess
import concurrent.futures
import sys
import re

CMD_TIMEOUT = 30
MAX_WORKERS = 8

DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

try:
    # List command
    parallel_commands = [
        '''curl -s "https://rapiddns.io/subdomain/TARGET?full=1#result" | awk -v RS='<[^>]+>' '/TARGET/' |grep "\w.*TARGET$"| sort -u >>TARGET-rapiddns.txt''',
        '''curl -s "https://jldc.me/anubis/subdomains/TARGET" | jq -r '.[]' 2>/dev/null | sort -u >>TARGET-jldc.txt''',
        '''curl -s "https://crt.sh/?q=%25.TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >>TARGET-crt.txt''',
        '''curl -s "https://urlscan.io/domain/TARGET" | grep "/domain" | grep TARGET | grep -v "<span" | cut -d"/" -f3 | cut -d">" -f1 | sed 's/"//g' | sort -u >>TARGET-urlscan.txt''',
        '''curl -s "https://api.hackertarget.com/hostsearch/?q=TARGET" | cut -d, -f1 | sort -u >>TARGET-hackertarget.txt''',
        '''curl -s "http://web.archive.org/cdx/search/cdx?url=*.TARGET&output=text&fl=original&collapse=urlkey" | cut -d/ -f3 | sort -u >>TARGET-webarchive.txt''',
        '''curl -s "https://freeapi.robtex.com/pdns/forward/TARGET" | jq -r '.rrdata' 2>/dev/null | sort -u >>TARGET-robtex.txt''',
    ]

    final_command = '''cat TARGET-*.txt | sort -u > TARGET.txt; cat -n TARGET.txt'''

    def exe_cmd(command_str: str):
        str_format = command_str.replace('TARGET', TARGET)
        print('[ + ] PROCESS:', str_format)
        try:
            proc = subprocess.run(
                str_format, capture_output=True, shell=True, timeout=CMD_TIMEOUT
            )
            result = proc.stdout.decode('utf-8', errors='replace')
            if proc.returncode != 0 and proc.stderr:
                print('[ ! ] STDERR:', proc.stderr.decode('utf-8', errors='replace').strip())
            if result:
                print(result)
        except subprocess.TimeoutExpired:
            print(f'[ ! ] TIMEOUT ({CMD_TIMEOUT}s):', str_format)
        except Exception as e:
            print(f'[ ! ] ERROR: {e}')

    # Using as command line
    if __name__ == '__main__':
        if len(sys.argv) == 2:
            TARGET = sys.argv[1]

            if not DOMAIN_PATTERN.match(TARGET):
                print('[ ! ] Invalid domain:', TARGET)
                sys.exit(1)

            subprocess.run(f'rm -f {TARGET}-*.txt {TARGET}.txt', shell=True)

            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(exe_cmd, cmd) for cmd in parallel_commands]
                concurrent.futures.wait(futures)

            exe_cmd(final_command)

except KeyboardInterrupt:
    pass
