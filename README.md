# SimpleReconSubdomain v2

<center>

![Screenshot](/assets/screenshot/banner.png)

[![Python](https://img.shields.io/badge/python-3.10+-yellow.svg)](https://www.python.org/)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20macOS-orange.svg)]()
[![License](https://img.shields.io/github/license/MrCl0wnLab/SimpleReconSubdomain?color=blue)]()

</center>

Developed to facilitate domain enumeration with minimal effort, whether using third-party APIs or DNS queries.

- Passive and active subdomain enumeration tool for OSINT and reconnaissance workflows.
Built with async Python - queries up to 17 sources in parallel with no external dependencies like `curl` or `jq`.



```
Author:   MrCl0wn
Blog:     https://blog.mrcl0wn.com
GitHub:   https://github.com/MrCl0wnLab
Twitter:  https://twitter.com/MrCl0wnLab
```


---

## WARNING
```
 +------------------------------------------------------------------------------+
 |  [!] Legal disclaimer: Usage of SimpleReconSubdomain for attacking           |
 |  targets without prior mutual consent is illegal.                            |
 |  It is the end user's responsibility to obey all applicable                  |
 |  local, state and federal laws.                                              |
 |  Developers assume no liability and are not responsible for any misuse or    |
 |  damage caused by this program.                                              |
 +------------------------------------------------------------------------------+
```

## Table of Contents

- [Installation](#installation)
- [API Keys](#api-keys)
- [Usage](#usage)
- [Passive vs Active Modules](#passive-vs-active-modules)
- [Sources](#sources)
- [DNS Brute-force and Wordlists](#dns-brute-force-and-wordlists)
- [Output Formats](#output-formats)
- [Chaining with Other Tools](#chaining-with-other-tools)
- [Creating a New Module](#creating-a-new-module)

---

## Installation

```bash
git clone https://github.com/MrCl0wnLab/SimpleReconSubdomain
cd SimpleReconSubdomain
pip install -r requirements.txt
```

**Dependencies** (`requirements.txt`):

| Package | Purpose |
|---|---|
| `httpx` | Async HTTP client for all passive sources |
| `aiodns` | Async DNS resolver for brute-force |
| `dnspython` | Zone transfer (AXFR) and DNS record mining |

---

## API Keys

API keys are stored in a single JSON file: `config/api_keys.json`.
I recommend this file is excluded from git (`.gitignore`) to prevent credential leaks.

```json
{
    "alienvault_otx":        "",
    "hackertarget":          "",
    "urlscan":               "",
    "virustotal":            "",
    "securitytrails":        "",
    "shodan":                "",
    "github_token":          "",
    "censys_token":          "",
    "grayhatwarfare_token":  "",
    "leakix_token":          "",
    "fullhunt_token":        ""
}
```

Fill in the keys you have. Sources with empty keys still run if they support unauthenticated access (e.g. `hackertarget`, `urlscan`, `alienvault`). Sources that require a key (`virustotal`, `securitytrails`, `censys`, `shodan`) return zero results if the key is missing.

**Where to get each key:**

| Key | URL |
|---|---|
| `alienvault_otx` | https://otx.alienvault.com → Settings → API Integration |
| `hackertarget` | https://hackertarget.com/membership |
| `urlscan` | https://urlscan.io/user/signup |
| `virustotal` | https://www.virustotal.com/gui/join-us |
| `securitytrails` | https://securitytrails.com/app/account |
| `shodan` | https://account.shodan.io |
| `censys_token` | https://search.censys.io/account/api → Personal Access Tokens |
| `github_token` | https://github.com/settings/tokens (scope: `public_repo`) |
| `grayhatwarfare_token` | https://grayhatwarfare.com/account |
| `leakix_token` | https://leakix.net/login → API Keys |
| `fullhunt_token` | https://fullhunt.io/user/api |

---

## Usage

### Basic

```bash
# Single domain
python simplerecon.py -d target.com

# List of domains
python simplerecon.py -l domains.txt

# List available sources
python simplerecon.py --list-sources
```
<center>

![Screenshot](/assets/screenshot/img.png)

</center>


### OSINT Context Examples

**Bug bounty - map a company's external attack surface:**
```bash
python simplerecon.py -d megacorp.com --sources crtsh,virustotal,shodan,censys --output json --outfile megacorp_subs.json
```

**Corporate intelligence - passive only, no DNS traffic to target:**
```bash
python simplerecon.py -d targetcorp.com --no-passive=False --sources crtsh,certspotter,wayback,alienvault,securitytrails
```

**Asset discovery from a known domain list:**
```bash
python simplerecon.py -l scope.txt --output json --outfile all_subs.json --timeout 60
```

**Full enumeration with brute-force and live verification:**
```bash
python simplerecon.py -d target.com \
  --brute wordlists/subdomains-top1million-20000.txt \
  --permute \
  --verify-live \
  --output json \
  --outfile target_full.json
```

**DNS zone transfer attempt (active, noisy):**
```bash
python simplerecon.py -d target.com --sources zone_transfer,dns_mining
```

**Quiet mode - pipe subdomains directly to another tool:**
```bash
python simplerecon.py -d target.com --no-banner | httpx -silent
```


### All Flags

```bash
Target:
  -d DOMAIN          Single target domain
  -l FILE            File with one domain per line

Output:
  -o {txt,json,csv}  Output format (default: txt)
  --outfile FILE     Write output to file

Performance:
  -t N               Thread multiplier for brute-force (default: 8)
  --timeout N        HTTP/DNS timeout in seconds (default: 30)
  --rate-limit N     Max concurrent requests per source (0 = unlimited)

Source control:
  --sources LIST     Comma-separated sources (default: all)
  --no-passive       Skip passive sources; run active/brute only
  --list-sources     Print all sources with descriptions and exit

Brute-force:
  --brute WORDLIST   Wordlist path for DNS brute-force
  --resolvers FILE   Custom DNS resolver IPs (one per line)
  --permute          Generate Altdns-style permutations from found subdomains

Post-processing:
  --verify-live      Check which subdomains respond to HTTP/HTTPS

Display:
  -v, --verbose      Show zero-result sources and errors
  -q, --quiet        Results only; suppress all process messages
  --no-banner        Suppress banner and all process output (clean pipe mode)
  --no-color         Disable ANSI colors
```

<center>

![Screenshot](/assets/screenshot/img3.png)

</center>

---

## Passive vs Active Modules

### Passive

Passive sources query **third-party databases, APIs, and public indexes**. No packet is sent to the target's infrastructure.

- Safe to run during passive recon phases
- Invisible to the target's security monitoring
- Examples: Certificate Transparency logs, Shodan, VirusTotal, Wayback Machine

### Active

Active sources **communicate directly with the target's DNS servers**. The target can observe this traffic.

| Module | What it does | Detectable? |
|---|---|---|
| `zone_transfer` | Attempts AXFR on all nameservers of the target | Yes - connects to target NS |
| `dns_mining` | Queries SPF, DMARC, MX, TXT records of the target | Yes - DNS queries to target NS |

Active modules are **not included by default** in `--sources all`. To run them explicitly:

```bash
# Run only active sources
python simplerecon.py -d target.com --no-passive --sources zone_transfer,dns_mining

# Mix passive + specific active
python simplerecon.py -d target.com --sources crtsh,shodan,zone_transfer
```

> Zone transfer (AXFR) succeeds only if the target nameserver is misconfigured.
> Most modern servers will refuse it. When it works, it leaks the entire DNS zone.

---

## Sources

```
python simplerecon.py --list-sources
```

| Source | Requires key | Notes |
|---|---|---|
| `rapiddns` | No | DNS dataset |
| `jldc` | No | Anubis subdomain DB |
| `crtsh` | No | Certificate Transparency |
| `certspotter` | No | Certificate Transparency |
| `urlscan` | Optional | Higher rate limit with key |
| `hackertarget` | Optional | Higher rate limit with key |
| `wayback` | No | web.archive.org CDX API |
| `robtex` | No | Passive DNS |
| `alienvault` | Optional | OTX threat intelligence |
| `bufferover` | No | Rapid7 FDNS via TLS |
| `virustotal` | Required | VT subdomains endpoint |
| `securitytrails` | Required | DNS history |
| `censys` | Required | Certificate search |
| `shodan` | Required | DNS domain lookup |
| `awsbucket` | Required | GrayHatWarfare — public cloud buckets (AWS/Azure/GCP) |
| `leakix` | Optional | LeakIX — exposed services and cloud assets |
| `fullhunt` | Required | FullHunt — full internet host & subdomain index |
| `zone_transfer` | No | Active: AXFR attempt |
| `dns_mining` | No | Active: SPF/MX/DMARC records |

<center>

![Screenshot](/assets/screenshot/img2.png)

</center>

---

## DNS Brute-force and Wordlists

### Recommended Wordlists

| Wordlist | Size | Use case |
|---|---|---|
| `subdomains-top1million-5000.txt` | 5k | Fast initial scan |
| `subdomains-top1million-20000.txt` | 20k | Standard bug bounty |
| `subdomains-top1million-110000.txt` | 110k | Thorough enumeration |
| `all.txt` (Jhaddix) | ~2M | Deep pentest |

**Download (SecLists):**
```bash
# Clone the full SecLists repository
git clone --depth 1 https://github.com/danielmiessler/SecLists.git

# Or download a single file
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt

# Jhaddix all.txt
wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/all.txt
```

**Download (Assetnote - generated from real CT log data):**
```bash
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
```

### Usage

```bash
# Brute-force with 20k wordlist
python simplerecon.py -d target.com \
  --brute SecLists/Discovery/DNS/subdomains-top1million-20000.txt

# Increase concurrency for faster resolution
python simplerecon.py -d target.com \
  --brute wordlist.txt \
  --threads 20

# Use custom resolvers to avoid rate-limiting
python simplerecon.py -d target.com \
  --brute wordlist.txt \
  --resolvers resolvers.txt

# Combine passive + brute-force + permutation
python simplerecon.py -d target.com \
  --brute wordlist.txt \
  --permute
```

**Example `resolvers.txt`:**
```
1.1.1.1
8.8.8.8
9.9.9.9
208.67.222.222
```

Public resolver lists: https://github.com/trickest/resolvers

---

## Output Formats

### Terminal (default)

```
------------------------------------------------------------
[*] Enumerating: target.com
------------------------------------------------------------
[*] Running passive sources...
[*] [crtsh] +42 subdomains
[*] [virustotal] +17 subdomains
[*] [shodan] +8 subdomains
[*] [wayback] +3 subdomains

[+] Total unique subdomains found: 58

api.target.com
dev.target.com
mail.target.com
stage.target.com
vpn.target.com
...
```

### TXT file

```bash
python simplerecon.py -d target.com -o txt --outfile results/target.txt
```

`results/target.txt`:
```
api.target.com
dev.target.com
mail.target.com
stage.target.com
vpn.target.com
```

### JSON file

```bash
python simplerecon.py -d target.com -o json --outfile results/target.json
```

`results/target.json`:
```json
{
  "domain": "target.com",
  "timestamp": "2026-05-19T14:32:01.123456",
  "total": 58,
  "subdomains": [
    "api.target.com",
    "dev.target.com",
    "mail.target.com"
  ],
  "live_hosts": {
    "api.target.com": {
      "status": 200,
      "title": "API Gateway",
      "server": "nginx/1.24.0",
      "content_length": 1842
    }
  },
  "sources": {
    "crtsh": 42,
    "virustotal": 17,
    "shodan": 8,
    "wayback": 3
  }
}
```

### CSV file

```bash
python simplerecon.py -d target.com --verify-live -o csv --outfile results/target.csv
```

`results/target.csv`:
```
domain,subdomain,status,title,server
target.com,api.target.com,200,API Gateway,nginx/1.24.0
target.com,dev.target.com,302,,
target.com,mail.target.com,200,Webmail,Apache/2.4
target.com,vpn.target.com,403,Forbidden,
```

---

## Chaining with Other Tools

### httpx - HTTP probing

```bash
# Probe all found subdomains for live HTTP services
python simplerecon.py -d target.com --no-banner | httpx -silent -status-code -title -tech-detect

# Filter only 200 OK responses
python simplerecon.py -d target.com --no-banner | httpx -silent -mc 200
```

### nmap - port scan

```bash
# Save subdomains, then port scan
python simplerecon.py -d target.com -o txt --outfile subs.txt
nmap -iL subs.txt -p 80,443,8080,8443 -T4 --open

# One-liner via pipe
python simplerecon.py -d target.com --no-banner | nmap -iL - -p 80,443,22 -T4 --open
```

### nuclei - vulnerability scanning

```bash
# Find live hosts, then run nuclei templates
python simplerecon.py -d target.com --verify-live -o json --outfile subs.json
jq -r '.subdomains[]' subs.json | nuclei -t exposures/ -silent

# Direct pipe with httpx in the middle
python simplerecon.py -d target.com --no-banner \
  | httpx -silent \
  | nuclei -t cves/ -silent
```

### dnsx - DNS resolution

```bash
# Resolve all subdomains and show A records
python simplerecon.py -d target.com --no-banner | dnsx -silent -a -resp

# Find subdomains pointing to cloud services (potential takeover)
python simplerecon.py -d target.com --no-banner \
  | dnsx -silent -cname -resp \
  | grep -E 'amazonaws|azurewebsites|github.io|herokuapp'
```

### amass - complement results

```bash
# Run both tools and merge results
python simplerecon.py -d target.com -o txt --outfile simplerecon_out.txt
amass enum -passive -d target.com -o amass_out.txt
cat simplerecon_out.txt amass_out.txt | sort -u > merged.txt
echo "[+] Total unique: $(wc -l < merged.txt)"
```

### eyewitness - screenshot live hosts

```bash
python simplerecon.py -d target.com --verify-live -o txt --outfile subs.txt
eyewitness --web -f subs.txt --no-prompt -d screenshots/
```

---

## Creating a New Module

All sources inherit from `BaseSource` defined in `sources/base.py`.
The only required method is `fetch(domain)`, which must return a `set[str]`.

### New Passive Module

**1. Create** `sources/passive/myservice.py`:

```python
import httpx
from sources.base import BaseSource
from core.config import get_key


class MyService(BaseSource):
    NAME = 'myservice'
    REQUIRES_API_KEY = True  # set False if no key needed

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('myservice')  # reads from config/api_keys.json
        if not api_key:
            return set()

        url = f'https://api.myservice.com/subdomains/{domain}'
        headers = {'Authorization': f'Bearer {api_key}'}
        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    for entry in resp.json().get('data', []):
                        subdomains.add(entry['hostname'])
        except Exception:
            pass

        return self._filter(subdomains, domain)  # removes out-of-scope entries
```

**2. Add the key** to `config/api_keys.json`:

```json
{
    "myservice": "your-api-key-here"
}
```

**3. Register the source** in `core/engine.py`:

```python
from sources.passive.myservice import MyService

ALL_PASSIVE_SOURCES: dict = {
    ...
    'myservice': MyService,
}
```

**4. Register in** `cli/parser.py`:

```python
ALL_PASSIVE = [
    ...
    'myservice',  # requer API key (config/api_keys.json)
]
```

**5. Add to the** `print_sources()` description in `cli/parser.py`:

```python
passive_info = [
    ...
    ('myservice', 'My custom service  [API key obrigatória]'),
]
```

---

### New Active Module

Active modules interact directly with the target (DNS queries, TCP connections).
Use `asyncio.get_event_loop().run_in_executor()` for blocking I/O (like `dnspython`).

**1. Create** `sources/active/myactive.py`:

```python
import asyncio
from sources.base import BaseSource


class MyActive(BaseSource):
    NAME = 'myactive'

    async def fetch(self, domain: str) -> set[str]:
        # run_in_executor wraps blocking calls so they don't block the event loop
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run, domain)

    def _run(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                # parse TXT records and extract hostnames
                for txt_string in rdata.strings:
                    txt = txt_string.decode('utf-8', errors='ignore')
                    # ... custom parsing logic ...
        except Exception:
            pass
        return self._filter(subdomains, domain)
```

**2. Register in** `core/engine.py`:

```python
from sources.active.myactive import MyActive

ALL_ACTIVE_SOURCES: dict = {
    ...
    'myactive': MyActive,
}
```

**3. Register in** `cli/parser.py`:

```python
ALL_ACTIVE = ['zone_transfer', 'dns_mining', 'myactive']
```

**4. Add description** in `cli/parser.py` `print_sources()`:

```python
active_info = [
    ...
    ('myactive', 'My custom active DNS probe'),
]
```

---


## 📄 LICENÇA

Este projeto está licenciado sob a Licença Apache - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👨‍💻 AUTOR

**MrCl0wn**
- 🌐 **Blog**: [http://blog.mrcl0wn.com](http://blog.mrcl0wn.com)
- 🐙 **GitHub**: [@MrCl0wnLab](https://github.com/MrCl0wnLab)
- 🐦 **Twitter**: [@MrCl0wnLab](https://twitter.com/MrCl0wnLab)
- 📧 **Email**: mrcl0wnlab\@\gmail.com

---

<div align="center">

**⭐ Se este projeto foi útil, considere dar uma estrela!**

**💡 Sugestões e feedbacks são sempre bem-vindos!**

**💀 Hacker Hackeia!**

</div>


