# SimpleReconSubdomain v2

<center>

![Screenshot](/assets/screenshot/banner.png)



<p align="center">
  <a href="#/"><img src="https://img.shields.io/badge/python-3.12+-orange.svg"></a>
  <a href="#"><img src="https://img.shields.io/badge/version-2.0.0-green.svg"></a>
  <a href="#"><img src="https://img.shields.io/badge/Supported_OS-Linux-orange.svg"></a>
  <a href="#"><img src="https://img.shields.io/badge/Supported_OS-Mac-orange.svg"></a>
  <a href="#"><img src="https://img.shields.io/badge/Apache-blue.svg"></a>
</p>

<p align="center">
  <a href="https://github.com/MrCl0wnLab/SimpleReconSubdomain/blob/main/LICENSE"><img src="https://img.shields.io/github/license/MrCl0wnLab/SimpleReconSubdomain?color=blue"></a>
  <a href="https://github.com/MrCl0wnLab/SimpleReconSubdomain/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/MrCl0wnLab/SimpleReconSubdomain"></a>
  <a href="https://github.com/MrCl0wnLab/SimpleReconSubdomain/issues"><img src="https://img.shields.io/github/issues-raw/MrCl0wnLab/SimpleReconSubdomain"></a>
  <a href="https://github.com/MrCl0wnLab/SimpleReconSubdomain/network/members"><img src="https://img.shields.io/github/forks/MrCl0wnLab/SimpleReconSubdomain"></a>
  <img src="https://img.shields.io/github/stars/MrCl0wnLab/SimpleReconSubdomain.svg?style=social" title="Stars" /> 
</p>

</center>

Passive and active subdomain enumeration tool for OSINT and reconnaissance workflows.
Built with async Python — queries **25 sources** (21 passive + 4 active) in parallel with no external shell dependencies.

Techniques inspired by **subfinder**, **amass** and **puredns**:
multi-probe wildcard detection, DNSSEC NSEC zone walking, TLS SAN extraction, SRV record mining, two-pass trusted-resolver validation, and recursive enumeration.

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
- [DNS Brute-force](#dns-brute-force)
- [Advanced Techniques](#advanced-techniques)
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
| `httpx` | Async HTTP client for all passive sources and resolver URL download |
| `aiodns` | Async DNS resolver for brute-force and validation |
| `dnspython` | Zone transfer (AXFR), DNS record mining, NSEC zone walking, SRV enumeration |

---

## API Keys

API keys are stored in `config/api_keys.json` (gitignored to prevent leaks).

```json
{
    "alienvault_otx":        "",
    "hackertarget":          "",
    "urlscan":               "",
    "virustotal":            "",
    "securitytrails":        "",
    "shodan":                "",
    "github_token":          "",
    "censys_id":             "",
    "censys_secret":         "",
    "grayhatwarfare_token":  "",
    "leakix_token":          "",
    "fullhunt_token":        "",
    "chaos_key":             "",
    "c99_key":               "",
    "netlas_key":            ""
}
```

Fill in the keys you have. Sources with empty keys still run if they support unauthenticated access (`hackertarget`, `urlscan`, `alienvault`, `dnsdumpster`, `commoncrawl`). Sources marked as requiring a key return zero results when the key is missing.

**Where to get each key:**

| Key | URL |
|---|---|
| `alienvault_otx` | https://otx.alienvault.com → Settings → API Integration |
| `hackertarget` | https://hackertarget.com/membership |
| `urlscan` | https://urlscan.io/user/signup |
| `virustotal` | https://www.virustotal.com/gui/join-us |
| `securitytrails` | https://securitytrails.com/app/account |
| `shodan` | https://account.shodan.io |
| `censys_id` / `censys_secret` | https://search.censys.io/account/api |
| `github_token` | https://github.com/settings/tokens (scope: `public_repo`) |
| `grayhatwarfare_token` | https://grayhatwarfare.com/account |
| `leakix_token` | https://leakix.net/login → API Keys |
| `fullhunt_token` | https://fullhunt.io/user/api |
| `chaos_key` | https://chaos.projectdiscovery.io → API Key |
| `c99_key` | https://api.c99.nl → Sign up |
| `netlas_key` | https://app.netlas.io/profile/ → API Keys |

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

**Bug bounty — map external attack surface (passive only):**
```bash
python simplerecon.py -d megacorp.com \
  --sources crtsh,virustotal,shodan,censys,github,chaos \
  --output json --outfile megacorp_subs.json
```

**Full enumeration — passive + brute-force + live verification:**
```bash
python simplerecon.py -d target.com \
  --brute wordlists/subdomains-top1million-20000.txt \
  --resolvers config/resolvers.txt \
  --wildcard-tests 5 \
  --validate-resolvers \
  --verify-live \
  --output json \
  --outfile target_full.json
```

**PureDNS-style mass brute-force with community resolver list:**
```bash
python simplerecon.py -d target.com \
  --brute wordlists/all.txt \
  --resolvers https://public-dns.info/nameservers-all.txt \
  --check-resolvers \
  --validate-resolvers \
  --threads 40
```

**Deep recon — include active sources and recursive enumeration:**
```bash
python simplerecon.py -d target.com \
  --sources crtsh,certspotter,github,chaos,nsec_walk,srv_enum \
  --brute wordlists/top5000.txt \
  --recursive --recursive-depth 2 \
  --verify-live \
  --output json --outfile deep_recon.json
```

**DNSSEC zone walking (requires NSEC, not NSEC3):**
```bash
python simplerecon.py -d target.com --sources nsec_walk -v
```

**Asset discovery from a domain list:**
```bash
python simplerecon.py -l scope.txt --output json --outfile all_subs.json --timeout 60
```

**Quiet mode — pipe subdomains directly to another tool:**
```bash
python simplerecon.py -d target.com --no-banner | httpx -silent
```


### All Flags

```
Target:
  -d DOMAIN              Single target domain
  -l FILE                File with one domain per line

Output:
  -o {txt,json,csv}      Output format (default: txt)
  --outfile FILE         Write output to file

Performance:
  -t N                   Thread multiplier for brute-force concurrency (default: 8)
  --timeout N            HTTP/DNS timeout in seconds (default: 30)
  --rate-limit N         Max concurrent HTTP requests per source (0 = unlimited)

Source control:
  --sources LIST         Comma-separated sources (default: all)
  --no-passive           Skip passive sources; run active/brute only
  --list-sources         Print all sources with descriptions and exit

Brute-force:
  --brute WORDLIST       Wordlist path for DNS brute-force
  --resolvers FILE_OR_URL
                         DNS resolver IPs — local file or https:// URL
                         (e.g. config/resolvers.txt or https://public-dns.info/nameservers-all.txt)
  --check-resolvers      Test each resolver against example.com before brute-force;
                         remove non-responsive ones (PureDNS technique)
  --wildcard-tests N     Random probes for wildcard detection (default: 3)
                         Higher values reduce false negatives on load-balanced DNS
  --validate-resolvers   Re-validate results against Google/Cloudflare after brute-force
                         to eliminate DNS-poisoned false positives (PureDNS two-pass)
  --permute              Generate Altdns-style permutations from found subdomains

Post-processing:
  --verify-live          HTTP/HTTPS probe; also extracts TLS certificate SANs (Amass technique)
  --recursive            Re-enumerate discovered subdomains as new targets (Subfinder technique)
  --recursive-depth N    Max recursion depth when --recursive is enabled (default: 1)

Display:
  -v [LEVEL]             Verbose level 1–4 (1=zero results, 2=+HTTP codes, 3=+body, 4=+exceptions)
  -q, --quiet            Results only; suppress all process messages
  --no-banner            Suppress banner and all process output (clean pipe mode)
  --no-color             Disable ANSI colors
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
- Examples: Certificate Transparency logs, Shodan, VirusTotal, GitHub code search, Common Crawl

### Active

Active sources **communicate directly with the target's DNS servers**. The target can observe this traffic.

| Module | What it does | Detection level |
|---|---|---|
| `zone_transfer` | AXFR attempt on all nameservers | **High** — connects to target NS |
| `dns_mining` | SPF / DMARC / MX / TXT record queries | **Moderate** — DNS queries to target NS |
| `nsec_walk` | DNSSEC NSEC chain walking to enumerate entire zone | **High** — queries authoritative NS directly |
| `srv_enum` | SRV record enumeration for ~70 common service prefixes | **Moderate** — DNS queries to public resolvers |

Active modules are included in `--sources all`. To run them explicitly:

```bash
# Run only active sources
python simplerecon.py -d target.com --no-passive --sources zone_transfer,dns_mining,nsec_walk,srv_enum

# Mix passive + specific active
python simplerecon.py -d target.com --sources crtsh,shodan,nsec_walk,srv_enum
```

> **Zone transfer (AXFR)** succeeds only if the target nameserver is misconfigured. When it works, it leaks the entire DNS zone.
>
> **NSEC zone walking** only works when the domain uses NSEC (not NSEC3). NSEC3 uses hashed names and blocks enumeration. The module detects this automatically and exits gracefully.

---

## Sources

```bash
python simplerecon.py --list-sources
```

### Passive Sources (21)

| Source | Requires key | Notes |
|---|---|---|
| `rapiddns` | No | DNS dataset |
| `jldc` | No | Anubis subdomain DB |
| `crtsh` | No | Certificate Transparency |
| `certspotter` | No | Certificate Transparency |
| `urlscan` | Optional | Higher rate limit with key |
| `hackertarget` | Optional | Higher rate limit with key |
| `wayback` | No | web.archive.org CDX API |
| `commoncrawl` | No | Common Crawl CDX API — independent historical crawl data |
| `robtex` | No | Passive DNS |
| `alienvault` | Optional | OTX threat intelligence |
| `bufferover` | No | Rapid7 FDNS via TLS |
| `dnsdumpster` | No | DNS recon tool (web scraping) |
| `github` | Required | Code search for hardcoded domain references |
| `virustotal` | Required | VT subdomains endpoint |
| `securitytrails` | Required | DNS history |
| `censys` | Required | Certificate search |
| `shodan` | Required | DNS domain lookup |
| `grayhatwarfare` | Required | Public cloud buckets (AWS/Azure/GCP) |
| `leakix` | Optional | Exposed services and cloud assets |
| `fullhunt` | Required | Full internet host & subdomain index |
| `chaos` | Required | ProjectDiscovery continuously updated subdomain DB |
| `c99` | Required | C99.nl subdomain finder |
| `netlas` | Required | Internet-wide asset and subdomain discovery |

### Active Sources (4)

| Source | Requires key | Notes |
|---|---|---|
| `zone_transfer` | No | DNS Zone Transfer (AXFR) |
| `dns_mining` | No | SPF / DMARC / MX record mining |
| `nsec_walk` | No | DNSSEC NSEC zone walking |
| `srv_enum` | No | SRV record enumeration (~70 service prefixes) |

<center>

![Screenshot](/assets/screenshot/img2.png)

</center>

---

## DNS Brute-force

### Recommended Wordlists

| Wordlist | Size | Use case |
|---|---|---|
| `subdomains-top1million-5000.txt` | 5k | Fast initial scan |
| `subdomains-top1million-20000.txt` | 20k | Standard bug bounty |
| `subdomains-top1million-110000.txt` | 110k | Thorough enumeration |
| `best-dns-wordlist.txt` (Assetnote) | ~9M | Deep pentest |

```bash
# Clone SecLists
git clone --depth 1 https://github.com/danielmiessler/SecLists.git

# Or download a single file
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt

# Assetnote wordlist (generated from real CT log data)
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
```

### Custom DNS Resolvers

By default the tool uses 6 built-in resolvers (Google, Cloudflare, Quad9, OpenDNS). For large-scale brute-force, supply a bigger list:

```bash
# Bundled list (~30 verified public resolvers)
python simplerecon.py -d target.com --brute wordlist.txt \
  --resolvers config/resolvers.txt

# Download a community list on-the-fly (7000+ resolvers)
python simplerecon.py -d target.com --brute wordlist.txt \
  --resolvers https://public-dns.info/nameservers-all.txt

# With health check — filters dead resolvers before brute-force
python simplerecon.py -d target.com --brute wordlist.txt \
  --resolvers https://public-dns.info/nameservers-all.txt \
  --check-resolvers
```

`--resolvers` accepts:
- A local file path (`config/resolvers.txt`, one IP per line, comments with `#` supported, `ip:port` format accepted)
- An `http://` or `https://` URL (downloaded automatically via `httpx`)

The list is deduplicated and **shuffled** automatically to distribute load across all resolvers.

Other public resolver sources:
- https://github.com/trickest/resolvers
- https://public-dns.info/nameservers-all.txt

### Full Brute-force Example

```bash
# Fast — bundled resolvers, no validation
python simplerecon.py -d target.com \
  --brute wordlists/top5000.txt \
  --resolvers config/resolvers.txt \
  --threads 20

# Thorough — community resolvers, health check, two-pass validation
python simplerecon.py -d target.com \
  --brute wordlists/subdomains-top1million-20000.txt \
  --resolvers https://public-dns.info/nameservers-all.txt \
  --check-resolvers \
  --wildcard-tests 5 \
  --validate-resolvers \
  --threads 30
```

---

## Advanced Techniques

### Multi-probe Wildcard Detection (PureDNS)

Instead of a single random-subdomain probe (unreliable under DNS load balancing), the tool fires `--wildcard-tests N` probes and confirms wildcard only when ≥ ceil(N/2) resolve. The **union of all returned IPs** is used as the filter set during brute-force.

```bash
python simplerecon.py -d target.com --brute wordlist.txt --wildcard-tests 5
```

### Two-pass Trusted Resolver Validation (PureDNS)

After mass brute-force with cheap public resolvers, re-validate against Google/Cloudflare only. Eliminates false positives from DNS poisoning on untrusted resolvers.

```bash
python simplerecon.py -d target.com --brute wordlist.txt --validate-resolvers
```

### TLS Certificate SAN Extraction (Amass)

During `--verify-live`, the tool performs a raw SSL handshake on port 443 and extracts **Subject Alternative Names** from the server certificate. Newly discovered hostnames are added back to the subdomain set.

```bash
python simplerecon.py -d target.com --verify-live --output json --outfile out.json
# JSON output includes "tls_sans": ["cdn.target.com", "api.target.com", ...] per live host
```

### DNSSEC NSEC Zone Walking (Amass)

NSEC records form a sorted linked list of every name in the DNS zone. The `nsec_walk` source traverses the chain to enumerate the entire zone without a zone transfer. Works only when the domain uses **NSEC** (not NSEC3 — the module detects and reports this automatically).

```bash
python simplerecon.py -d target.com --sources nsec_walk -v
# Example domain with NSEC: nlnetlabs.nl
```

### SRV Record Enumeration (Amass)

Queries ~70 common SRV prefixes (`_http._tcp`, `_ldap._tcp`, `_kerberos._tcp`, `_autodiscover._tcp`, `_sip._tcp`, etc.). SRV records frequently reveal internal hostnames not found through passive sources.

```bash
python simplerecon.py -d target.com --sources srv_enum -v
```

The prefix list is in `config/srv_prefixes.json` — edit it to add domain-specific services.

### Recursive Enumeration (Subfinder)

After enumerating `target.com`, discovered subdomains like `api.target.com` are themselves used as enumeration targets to find deeper entries (`v2.api.target.com`, `internal.api.target.com`, etc.).

```bash
python simplerecon.py -d target.com --recursive --recursive-depth 2
```

### GitHub Code Search

Searches GitHub for source code files containing references to the target domain (hardcoded subdomains in configs, `.env` files, CI scripts). Requires a `github_token` in `config/api_keys.json`.

```bash
python simplerecon.py -d target.com --sources github -v
```

---

## Output Formats

### Terminal (default)

```
------------------------------------------------------------
[*] Enumerating: target.com
------------------------------------------------------------
[*] Running passive sources...
[*] [crtsh] +42 subdomains
[*] [github] +8 subdomains
[*] [chaos] +12 subdomains
[*] [nsec_walk] +31 subdomains
[*] [srv_enum] +3 subdomains

[+] Total unique subdomains found: 72

api.target.com
dev.target.com
mail.target.com
...
```

### JSON

```bash
python simplerecon.py -d target.com --verify-live -o json --outfile results/target.json
```

```json
{
  "domain": "target.com",
  "timestamp": "2026-05-27T14:32:01.123456",
  "total": 72,
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
      "content_length": 1842,
      "url": "https://api.target.com",
      "tls_sans": ["api.target.com", "*.api.target.com", "cdn.target.com"]
    }
  },
  "sources": {
    "crtsh": 42,
    "github": 8,
    "chaos": 12,
    "nsec_walk": 31,
    "srv_enum": 3,
    "tls_sans": 5
  }
}
```

### CSV

```bash
python simplerecon.py -d target.com --verify-live -o csv --outfile results/target.csv
```

```
domain,subdomain,status,title,server,tls_sans
target.com,api.target.com,200,API Gateway,nginx/1.24.0,api.target.com|*.api.target.com
target.com,mail.target.com,200,Webmail,Apache/2.4,
```

### TXT

```bash
python simplerecon.py -d target.com -o txt --outfile results/target.txt
```

---

## Chaining with Other Tools

### httpx — HTTP probing

```bash
python simplerecon.py -d target.com --no-banner | httpx -silent -status-code -title -tech-detect

# Filter only 200 OK
python simplerecon.py -d target.com --no-banner | httpx -silent -mc 200
```

### nmap — port scan

```bash
python simplerecon.py -d target.com -o txt --outfile subs.txt
nmap -iL subs.txt -p 80,443,8080,8443 -T4 --open
```

### nuclei — vulnerability scanning

```bash
python simplerecon.py -d target.com --no-banner \
  | httpx -silent \
  | nuclei -t cves/ -silent
```

### dnsx — DNS resolution and CNAME chasing

```bash
# Find potential subdomain takeovers
python simplerecon.py -d target.com --no-banner \
  | dnsx -silent -cname -resp \
  | grep -E 'amazonaws|azurewebsites|github.io|herokuapp'
```

### eyewitness — screenshots

```bash
python simplerecon.py -d target.com --verify-live -o txt --outfile subs.txt
eyewitness --web -f subs.txt --no-prompt -d screenshots/
```

### SimpleReconSubdomain — enrichment and automation

[SimpleReconSubdomain](https://github.com/MrCl0wnLab/SimpleReconSubdomain) (`strx`) is a modular automation tool using a `{STRING}` placeholder. It pairs naturally with SimpleReconSubdomain via pipes.

```bash
# HTTP probe all discovered subdomains
python simplerecon.py -d target.com --no-banner \
  | strx -st "echo {STRING}" -module "clc:http_probe" -pm

# Resolve subdomains → extract IPs → Shodan lookup per IP
python simplerecon.py -d target.com --no-banner \
  | strx -st "echo {STRING}" -module "clc:dns" -pm \
  | strx -st "echo {STRING}" -module "ext:ip" -pm \
  | strx -st "echo {STRING}" -module "clc:shodan" -pm

# Enrich with DNS + geolocation in a single chain
python simplerecon.py -d target.com --no-banner \
  | strx -st "echo {STRING}" -module "clc:dns|ext:ip|clc:geoip" -pm

# Send live subdomains to Telegram
python simplerecon.py -d target.com --no-banner \
  | strx -st "echo {STRING}" -module "con:telegram" -pm
```

---

## Creating a New Module

All sources inherit from `BaseSource` in `sources/base.py`. Drop the file in `sources/passive/` or `sources/active/` — no other file needs editing.

The class name must be the **title-cased filename** (e.g. `myservice.py` → class `Myservice`), and `NAME` must equal the filename without `.py`.

### New Passive Source

```python
# sources/passive/myservice.py
import httpx
from sources.base import BaseSource
from core.config import get_key


class Myservice(BaseSource):
    NAME = 'myservice'
    DESCRIPTION = 'My custom service'
    API_TOKEN_IS_REQUIREMENT = True

    async def fetch(self, domain: str) -> set[str]:
        api_key = get_key('myservice')
        if not api_key:
            return set()

        subdomains: set[str] = set()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await self._get(client, f'https://api.myservice.com/subdomains/{domain}')
            if resp.status_code == 200:
                for entry in resp.json().get('data', []):
                    subdomains.add(entry['hostname'])

        return self._filter(subdomains, domain)
```

Add the key to `config/api_keys.json`:
```json
{ "myservice": "your-api-key-here" }
```

### New Active Source

Use `asyncio.wait_for` + `run_in_executor` for blocking DNS calls to prevent hangs:

```python
# sources/active/myactive.py
import asyncio
from sources.base import BaseSource


class Myactive(BaseSource):
    NAME = 'myactive'
    DESCRIPTION = 'Active: custom DNS probe'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._run, domain),
                timeout=max(self.timeout, 30),
            )
        except asyncio.TimeoutError:
            self._vlog(1, 'timed out')
            return set()

    def _run(self, domain: str) -> set[str]:
        subdomains: set[str] = set()
        try:
            import dns.resolver
            # ... blocking dnspython calls here ...
        except Exception as exc:
            self._log_exc(exc)
        return self._filter(subdomains, domain)
```

---

## 📄 LICENÇA

Este projeto está licenciado sob a Licença Apache — veja o arquivo [LICENSE](LICENSE) para detalhes.

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
