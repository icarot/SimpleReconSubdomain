# SimpleReconSubdomain
Automated subdomain enumeration tool using multiple public APIs — no API key required.

[![Python 3.7](https://img.shields.io/badge/python-3.7-yellow.svg)](https://www.python.org/)
[![Build](https://img.shields.io/badge/Supported_OS-Linux-orange.svg)]()
[![Build](https://img.shields.io/badge/Supported_OS-Mac-orange.svg)]()
![GitHub](https://img.shields.io/github/license/MrCl0wnLab/SenderMailgunPython?color=blue)
```
Autor:    MrCl0wn
Blog:     https://blog.mrcl0wn.com
GitHub:   https://github.com/MrCl0wnLab
Twitter:  https://twitter.com/MrCl0wnLab
Email:    mrcl0wnlab@gmail.com
```

## USE
```bash
python tool.py {domain}
python tool.py fbi.gov
```
![Screenshot](assets/img1.png)
![Screenshot](assets/img2.png)

## SOURCES
All queries run in parallel (up to 8 threads) with a 30s timeout per request.

| Source | Type |
|---|---|
| [RapidDNS](https://rapiddns.io) | DNS dataset |
| [Anubis (JLDC)](https://jldc.me) | Subdomain DB |
| [crt.sh](https://crt.sh) | Certificate Transparency |
| [URLScan.io](https://urlscan.io) | Web scanner |
| [HackerTarget](https://hackertarget.com) | Host search |
| [Wayback Machine](https://web.archive.org) | Web archive |
| [Robtex](https://robtex.com) | Passive DNS |

## TARGET IS A MAGIC STRING
`TARGET` is a placeholder replaced at runtime with the domain passed as argument.

```bash
curl -s "https://rapiddns.io/subdomain/TARGET?full=1#result" | awk -v RS='<[^>]+>' '/TARGET/' | grep "\w.*TARGET$" | sort -u >>TARGET-rapiddns.txt

curl -s "https://jldc.me/anubis/subdomains/TARGET" | jq -r '.[]' 2>/dev/null | sort -u >>TARGET-jldc.txt

curl -s "https://crt.sh/?q=%25.TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >>TARGET-crt.txt

curl -s "https://urlscan.io/domain/TARGET" | grep "/domain" | grep TARGET | grep -v "<span" | cut -d"/" -f3 | cut -d">" -f1 | sed 's/"//g' | sort -u >>TARGET-urlscan.txt

curl -s "https://api.hackertarget.com/hostsearch/?q=TARGET" | cut -d, -f1 | sort -u >>TARGET-hackertarget.txt

curl -s "http://web.archive.org/cdx/search/cdx?url=*.TARGET&output=text&fl=original&collapse=urlkey" | cut -d/ -f3 | sort -u >>TARGET-webarchive.txt

curl -s "https://freeapi.robtex.com/pdns/forward/TARGET" | jq -r '.rrdata' 2>/dev/null | sort -u >>TARGET-robtex.txt

cat TARGET-*.txt | sort -u > TARGET.txt; cat -n TARGET.txt
```

## OUTPUT
```
TARGET-rapiddns.txt
TARGET-jldc.txt
TARGET-crt.txt
TARGET-urlscan.txt
TARGET-hackertarget.txt
TARGET-webarchive.txt
TARGET-robtex.txt
```

## OUTPUT SORT UNIQ
```
TARGET.txt
```

## REQUIREMENTS
```bash
pip install -r requirements.txt
# External: curl, jq, awk, sed
```
