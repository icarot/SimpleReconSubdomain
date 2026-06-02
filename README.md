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
  <a href="https://github.com/MrCl0wnLab/SimpleReconSubdomain/blob/master/LICENSE"><img src="https://img.shields.io/github/license/MrCl0wnLab/SimpleReconSubdomain?color=blue"></a>
  <a href="https://github.com/MrCl0wnLab/SimpleReconSubdomain/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/MrCl0wnLab/SimpleReconSubdomain"></a>
  <a href="https://github.com/MrCl0wnLab/SimpleReconSubdomain/issues"><img src="https://img.shields.io/github/issues-raw/MrCl0wnLab/SimpleReconSubdomain"></a>
  <a href="https://github.com/MrCl0wnLab/SimpleReconSubdomain/network/members"><img src="https://img.shields.io/github/forks/MrCl0wnLab/SimpleReconSubdomain"></a>
  <img src="https://img.shields.io/github/stars/MrCl0wnLab/SimpleReconSubdomain.svg?style=social" title="Stars" /> 
</p>

</center>

Passive and active subdomain enumeration tool for OSINT and reconnaissance workflows.
Built with async Python - queries **50 sources** (39 passive + 11 active) in parallel with no external shell dependencies.

Techniques inspired by **subfinder**, **amass**, **puredns** and **subjack**:
multi-probe wildcard detection, DNSSEC NSEC zone walking, TLS SAN extraction, SRV record mining, two-pass trusted-resolver validation, recursive enumeration, HTML/JS crawling with sourcemap mining, CAA record mining, robots.txt/sitemap harvesting, secondary NS brute-force, ASN-based PTR sweep, IP/cloud provider detection, wordlist learning from discovered names, and subdomain-takeover fingerprinting.

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
- [Profiles](#profiles)
- [Run-Config Presets](#run-config-presets)
- [Passive vs Active Modules](#passive-vs-active-modules)
- [Sources](#sources)
- [DNS Brute-force](#dns-brute-force)
- [Wordlist Learner — Pattern-derived candidates](#wordlist-learner--pattern-derived-candidates)
- [TLD Brute-force](#tld-brute-force)
- [Extras — External Hosts, IPs and URLs](#extras--external-hosts-ips-and-urls)
- [Network Mapping — Graph JSON and HTML visualization](#network-mapping--graph-json-and-html-visualization)
- [Markdown Report](#markdown-report)
- [Advanced Techniques](#advanced-techniques)
- [Subdomain Takeover Detection](#subdomain-takeover-detection)
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
| `beautifulsoup4` | HTML parsing for the `spider` active source (`<a>`, `<link>`, `<script>` extraction) |

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
    "netlas_key":            "",
    "onyphe_key":            "",
    "greynoise_key":         "",
    "fofa_key":              "",
    "pulsedive_key":         "",
    "intelx_key":            "",
    "publicwww_key":         "",
    "merklemap_key":         "",
    "bevigil_key":           "",
    "hunterhow_key":         "",
    "circl_user":            "",
    "circl_pass":            ""
}
```

Fill in the keys you have. Sources with empty keys still run if they support unauthenticated access (`hackertarget`, `urlscan`, `alienvault`, `dnsdumpster`, `commoncrawl`, `anubisdb`, `subdomaincenter`, `threatminer`, `fofa` free scrape, `urlhaus`, `circl`, `bing`). Sources marked as requiring a key return zero results when the key is missing.

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
| `onyphe_key` | https://www.onyphe.io/login/ → API |
| `greynoise_key` | https://viz.greynoise.io/account/ |
| `fofa_key` | https://fofa.so/userInfo |
| `pulsedive_key` | https://pulsedive.com/api/ |
| `intelx_key` | https://intelx.io/account?tab=developer |
| `publicwww_key` | https://publicwww.com/api.html |
| `merklemap_key` | https://www.merklemap.com/dashboard/api (paid subscription required) |
| `bevigil_key` | https://bevigil.com/osint-api → Sign up |
| `hunterhow_key` | https://hunter.how/api → Get API key |
| `circl_user` / `circl_pass` | https://www.circl.lu/services/passive-dns/ → Request access (optional; free unauthenticated tier available) |

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

# List available profiles (curated source groups)
python simplerecon.py --list-profiles

# Print built-in usage examples and exit
python simplerecon.py --list-examples

# Run a predefined profile (no need to spell out sources)
python simplerecon.py -d target.com --profile fast
python simplerecon.py -d target.com --profile osint --verify-live
```

<center>

![Screenshot](/assets/screenshot/img.png)

</center>


### OSINT Context Examples

**Bug bounty - map external attack surface (passive only):**
```bash
python simplerecon.py -d megacorp.com \
  --sources crtsh,virustotal,shodan,censys,github,chaos \
  --output json --outfile megacorp_subs.json
```

**Full enumeration - passive + brute-force + live verification:**
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

**Deep recon - include active sources and recursive enumeration:**
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

**Quiet mode - pipe subdomains directly to another tool:**
```bash
python simplerecon.py -d target.com --no-banner | httpx -silent
```


### All Flags

```
Target:
  -d DOMAIN              Single target domain
  -l FILE                File with one domain per line
  --stdin                Read domains from stdin (one per line); enables pipe-friendly use

Output:
  -o {txt,json,csv,ndjson,html,markdown}
                         Output format (default: txt).
                         ndjson   = one compact JSON line per subdomain - ideal for jq piping
                         html     = interactive network-map page (vis-network via CDN)
                         markdown = human-readable reconnaissance report
  --outfile FILE         Write output to file
  --network-map          Include network graph (nodes/edges) in JSON output.
                         Auto-enabled when -o html or --network-html is used.
  --network-html FILE    Write an HTML network-map visualization to FILE alongside the
                         main output. Combine with any -o format.

Performance:
  -t N                   Thread multiplier for brute-force concurrency (default: 8)
  --timeout N            HTTP/DNS timeout in seconds (default: 30)
  --rate-limit N         Max concurrent HTTP requests per source (0 = unlimited)

Network:
  --proxy URL            Route all HTTP requests through a proxy
                         (e.g. http://127.0.0.1:8080 or socks5://host:port)
  --user-agent UA        Override User-Agent for all source HTTP requests

Source control:
  --profile PROFILE      Run a predefined source group (fast, stealth, osint,
                         code, active, full). Overrides --sources.
  --sources LIST         Comma-separated sources (default: all)
  --exclude LIST         Comma-separated sources to exclude (applied after --sources/--profile)
  --no-passive           Skip passive sources; run active/brute only
  --list-sources         Print all sources with descriptions and exit
  --list-profiles        Print all profiles with their source sets and exit
  --list-examples        Print built-in usage examples and exit

Run-config:
  --config FILE          Load CLI argument defaults from a JSON preset file.
                         Only keys absent from the command line are applied;
                         explicit CLI flags always win.
                         Template: config/run_config.example.json

Brute-force:
  --brute WORDLIST       Wordlist path for DNS brute-force
  --resolvers FILE_OR_URL
                         DNS resolver IPs - local file or https:// URL
                         (e.g. config/resolvers.txt or https://public-dns.info/nameservers-all.txt)
  --check-resolvers      Test each resolver against example.com before brute-force;
                         remove non-responsive ones (PureDNS technique)
  --wildcard-tests N     Random probes for wildcard detection (default: 3)
                         Higher values reduce false negatives on load-balanced DNS
  --validate-resolvers   Re-validate results against Google/Cloudflare after brute-force
                         to eliminate DNS-poisoned false positives (PureDNS two-pass)
  --permute              Generate Altdns-style permutations from found subdomains
  --learn-words          Derive brute-force candidates from patterns in discovered names
                         (numeric sequences, environment families, geo variants, version bumps).
                         Runs after passive/active gathering, feeds into --brute when combined.
  --tld-brute [FILE]     Discover live TLD variants of the target (e.g. target.net, target.io).
                         Strips the current TLD, resolves {base}.{tld} for every entry in the
                         wordlist. Optional FILE overrides the default config/tlds.txt (~250 TLDs).
                         Results are stored separately as tld_variants in all output formats.

Extras:
  --show-extras          Surface elements found outside the target domain during enumeration:
                         external hosts (from certs, code repos, APIs), IPs (from --verify-live),
                         and crawled URLs (from spider). Shown as separate sections in all output formats.

Post-processing:
  --verify-live          HTTP/HTTPS probe; also extracts TLS certificate SANs (Amass technique)
                         and fingerprints potential subdomain takeovers (Subjack technique)
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

## Profiles

Profiles are curated source groups defined in [config/profiles.json](config/profiles.json). Use `--profile NAME` instead of typing long `--sources` lists. Profiles may also set defaults (e.g. `rate_limit`) automatically.

```bash
python simplerecon.py --list-profiles
python simplerecon.py -d target.com --profile fast
```

| Profile | Description | Sources |
|---|---|---|
| `fast` | Quick scan - fastest no-auth sources only | `crtsh`, `certspotter`, `hackertarget`, `rapiddns`, `jldc`, `alienvault`, `anubisdb`, `subdomaincenter`, `urlhaus`, `circl`, `bing` |
| `stealth` | Minimal footprint - passive only, rate-limited (`rate_limit=2`) | `crtsh`, `certspotter`, `wayback`, `commoncrawl`, `robtex`, `anubisdb` |
| `osint` | Code repos + threat intel + CT logs + asset DBs | `crtsh`, `certspotter`, `alienvault`, `virustotal`, `shodan`, `github`, `grep_app`, `threatminer`, `anubisdb`, `subdomaincenter`, `hackertarget`, `rapiddns`, `urlscan`, `bevigil`, `hunterhow`, `urlhaus`, `circl`, `bing` |
| `code` | Code search only | `github`, `grep_app` |
| `active` | Active techniques only | `zone_transfer`, `ns_brute`, `dns_mining`, `caa_enum`, `nsec_walk`, `srv_enum`, `spider`, `robots_sitemap`, `ptr_sweep`, `asn_sweep`, `vhost_probe` |
| `full` | All available passive and active sources | `all` |

Add or edit profiles by modifying [config/profiles.json](config/profiles.json):

```json
{
  "myprofile": {
    "description": "My custom set",
    "sources": ["crtsh", "github", "shodan"],
    "options": {"rate_limit": 5}
  }
}
```

---

## Run-Config Presets

A run-config is a JSON file that stores CLI argument defaults, allowing you to run repeatable scans without long command lines.

```bash
python simplerecon.py -d target.com --config config/run_config.example.json
python simplerecon.py -d target.com --config my_scan.json
```

**Precedence (highest → lowest):**
1. Explicit CLI flags (always win)
2. Values from the `--config` JSON file
3. Built-in argparse defaults

Only keys present in the JSON are applied; unknown keys are silently ignored so configs stay forward/backward compatible. A minimal config is perfectly valid — you only need to include the keys you want to set:

```json
{
  "profile": "osint",
  "verify_live": true,
  "output": "json",
  "outfile": "results.json"
}
```

The annotated template at [config/run_config.example.json](config/run_config.example.json) documents every available key. Copy and edit it to create your own preset.

```bash
# List-examples shows ready-to-copy command patterns
python simplerecon.py --list-examples
```

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
| `zone_transfer` | AXFR attempt on all nameservers | **High** - connects to target NS |
| `ns_brute` | Secondary NS discovery (SOA MNAME + common name brute-force) then AXFR/IXFR on every candidate | **High** - DNS queries to target NS |
| `dns_mining` | SPF / DMARC / MX / TXT record queries | **Moderate** - DNS queries to target NS |
| `caa_enum` | CAA record mining — `iodef:` field leaks internal hostnames and URLs | **Low** - single DNS query per target |
| `nsec_walk` | DNSSEC NSEC chain walking to enumerate entire zone | **High** - queries authoritative NS directly |
| `srv_enum` | SRV record enumeration for ~70 common service prefixes | **Moderate** - DNS queries to public resolvers |
| `spider` | BFS HTML crawler (depth 2, 100 pages): follows `<a href>` and `<link href>` links; also collects `<script src>` and `<link rel=modulepreload>` JS files; mines subdomains from JS content and follows `//# sourceMappingURL` / `X-SourceMap` references to `.map` files | **High** - direct HTTP requests to target |
| `robots_sitemap` | Fetches `robots.txt` (extracts `Sitemap:` directives and hostnames in paths) then recursively downloads and parses `sitemap.xml` / `<sitemapindex>` — extracts all `<loc>` hostnames | **Moderate** - direct HTTP to target |
| `ptr_sweep` | Reverse-DNS PTR sweep on /24 blocks containing target IPs | **Moderate** - DNS queries to public resolvers |
| `asn_sweep` | Looks up the target's ASN via bgp.he.net, fetches all owned CIDR prefixes, then PTR-sweeps every IP in each block | **Moderate** - HTTP to bgp.he.net + DNS PTR queries |
| `vhost_probe` | Virtual-host brute-force via HTTP Host-header fuzzing | **High** - direct HTTP requests to target |

Active modules are included in `--sources all`. To run them explicitly:

```bash
# Run only active sources
python simplerecon.py -d target.com --no-passive --sources zone_transfer,dns_mining,nsec_walk,srv_enum,spider

# Mix passive + specific active
python simplerecon.py -d target.com --sources crtsh,shodan,nsec_walk,srv_enum,spider

# Or just use the curated active profile
python simplerecon.py -d target.com --profile active
```

> **Zone transfer (AXFR)** succeeds only if the target nameserver is misconfigured. When it works, it leaks the entire DNS zone.
>
> **NSEC zone walking** only works when the domain uses NSEC (not NSEC3). NSEC3 uses hashed names and blocks enumeration. The module detects this automatically and exits gracefully.

---

## Sources

```bash
python simplerecon.py --list-sources
```

### Passive Sources (39)

| Source | Requires key | Notes |
|---|---|---|
| `rapiddns` | No | DNS dataset |
| `jldc` | No | Anubis subdomain DB |
| `crtsh` | No | Certificate Transparency |
| `certspotter` | No | Certificate Transparency |
| `merklemap` | Required | CT log aggregator (alternative to crt.sh) - paid subscription required |
| `anubisdb` | No | jonlu.ca passive DNS subdomain database |
| `subdomaincenter` | No | Netcraft-backed free subdomain index |
| `threatminer` | No | ThreatMiner passive DNS / threat intel |
| `urlscan` | Optional | Higher rate limit with key |
| `hackertarget` | Optional | Higher rate limit with key |
| `wayback` | No | web.archive.org CDX API (paginated, up to 200k entries) |
| `commoncrawl` | No | Common Crawl CDX API - independent historical crawl data |
| `robtex` | No | Passive DNS |
| `alienvault` | Optional | OTX threat intelligence |
| `bufferover` | No | Rapid7 FDNS via TLS |
| `dnsdumpster` | No | DNS recon tool (web scraping) |
| `github` | Required | Code search for hardcoded domain references |
| `grep_app` | No | grep.app GitHub code search |
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
| `onyphe` | Required | Cyber defense search engine |
| `greynoise` | Required | Internet noise / passive scanner data |
| `fofa` | Optional | FOFA internet asset search (free scrape fallback when no key) |
| `pulsedive` | Optional | Threat-intel observable lookup |
| `intelx` | Required | IntelligenceX leaked data search |
| `publicwww` | Required | Source-code search across the public web |
| `bevigil` | Required | BeVigil OSINT - subdomains extracted from mobile apps |
| `hunterhow` | Required | Hunter.how global asset database |
| `urlhaus` | No | URLhaus abuse.ch malicious URL database - no auth needed |
| `circl` | No (Optional Basic auth) | CIRCL Passive DNS - public free tier; key gives higher rate |
| `bing` | No | Bing search - multi-template UA-rotating anti-bot scraping |

### Active Sources (11)

| Source | Requires key | Notes |
|---|---|---|
| `zone_transfer` | No | DNS Zone Transfer (AXFR) on public nameservers |
| `ns_brute` | No | Secondary NS discovery (SOA MNAME + 16-prefix brute-force) + AXFR/IXFR on all candidates |
| `dns_mining` | No | SPF / DMARC / MX record mining |
| `caa_enum` | No | CAA `iodef:` field mining — leaks internal hostnames from `mailto:` and `https://` values |
| `nsec_walk` | No | DNSSEC NSEC zone walking |
| `srv_enum` | No | SRV record enumeration (~70 service prefixes) |
| `spider` | No | BFS HTML crawler + JS miner: follows `<a href>` / `<link href>` (depth 2, 100 pages), collects `<script src>` JS files, extracts subdomains from JS content, follows `.map` sourcemap references |
| `robots_sitemap` | No | `robots.txt` directives + recursive `sitemap.xml` / `<sitemapindex>` `<loc>` hostname extraction (max 20 sitemaps, depth 2) |
| `ptr_sweep` | No | Reverse-DNS PTR sweep on /24 blocks containing target IPs |
| `asn_sweep` | No | Resolves target ASN via bgp.he.net → fetches all owned IPv4 prefixes (≤/20) → PTR sweep |
| `vhost_probe` | No | Virtual-host brute-force via HTTP Host-header fuzzing (130+ word built-in list) |

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

# With health check - filters dead resolvers before brute-force
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
# Fast - bundled resolvers, no validation
python simplerecon.py -d target.com \
  --brute wordlists/top5000.txt \
  --resolvers config/resolvers.txt \
  --threads 20

# Thorough - community resolvers, health check, two-pass validation
python simplerecon.py -d target.com \
  --brute wordlists/subdomains-top1million-20000.txt \
  --resolvers https://public-dns.info/nameservers-all.txt \
  --check-resolvers \
  --wildcard-tests 5 \
  --validate-resolvers \
  --threads 30
```

---

## TLD Brute-force

`--tld-brute` discovers live registrations of the target domain under other TLDs (e.g. `target.net`, `target.io`, `target.com.br`). Useful for brand protection, typosquatting detection, and mapping the full domain portfolio of a target.

```bash
# Use the built-in wordlist (~250 TLDs)
python simplerecon.py -d target.com --tld-brute

# Use a custom TLD list
python simplerecon.py -d target.com --tld-brute custom_tlds.txt

# Combine with passive enumeration and live verification
python simplerecon.py -d target.com --tld-brute --verify-live -o json --outfile results.json
```

The tool strips the current TLD from the target (handling compound TLDs like `.co.uk` and `.com.br` automatically), then resolves `{base}.{tld}` for every entry in the wordlist. Only variants that resolve in DNS are returned.

Results appear in a separate `tld_variants` field in JSON/CSV/NDJSON output and are printed to the terminal at the end of each run.

The default wordlist is [config/tlds.txt](config/tlds.txt). Edit it or supply your own file with `--tld-brute FILE`.

---

## Wordlist Learner — Pattern-derived candidates

`--learn-words` analyses the subdomain names already discovered (from passive and active sources) and derives targeted brute-force candidates from the patterns it finds — without any static wordlist.

```bash
# Derive candidates from passive results, then resolve them
python simplerecon.py -d target.com --profile fast --learn-words

# Combine with a traditional wordlist (merged before resolution)
python simplerecon.py -d target.com --profile fast --learn-words --brute wordlists/top5000.txt

# Full pipeline: passive → learn → brute → live-check
python simplerecon.py -d target.com --profile osint --learn-words \
  --brute wordlists/subdomains-top1million-5000.txt \
  --verify-live -o json --outfile results.json
```

### What patterns are detected

| Pattern | Example input | Candidates generated |
|---------|---------------|---------------------|
| **Numeric sequences** | `api1`, `api2` | `api3` … `api9` (fills gaps and extends runs) |
| **Environment families** | `dev-api`, `dev-admin` | `staging-api`, `qa-api`, `prod-api`, `staging-admin` … |
| **Geo variants** | `cdn-us`, `cdn-eu` | `cdn-br`, `cdn-uk`, `cdn-de`, `cdn-sg` … |
| **Version bumps** | `app-v2` | `app-v1`, `app-v3` |
| **Token combinations** | `dev`, `api`, `eu` each in ≥2 names | missing cross-product pairs: `dev-eu`, `api-eu` … |

The learner returns only **new** candidates — names not already in the discovered set. When combined with `--brute`, the two word sets are merged before DNS resolution so only one brute-force pass runs.

---

## Extras — External Hosts, IPs and URLs

`--show-extras` surfaces elements collected during enumeration that fall outside the target domain. Useful for mapping partner infrastructure, discovering related assets, and understanding the broader ecosystem of a target.

```bash
# External hosts from CT logs + GitHub + APIs
python simplerecon.py -d target.com --sources crtsh,github --show-extras

# Spider: external hosts + all crawled URLs
python simplerecon.py -d target.com --sources spider --show-extras --no-banner

# Full run: external hosts, IPs from live check, crawled URLs
python simplerecon.py -d target.com --profile osint --verify-live --show-extras -o json --outfile out.json
```

### What gets collected

| Category | Source | Examples |
|---|---|---|
| **External hosts** | All 46 sources via `_filter()` | `partner.com`, `cdn.cloudfront.net`, `internal.corp` found in cert SANs or code |
| **IPs** | `--verify-live` (resolved per subdomain) | `1.2.3.4`, `2606:4700::` |
| **URLs** | Spider BFS (visited pages + JS + `.map` files) | `https://target.com/api/v1`, `https://target.com/static/app.js` |

### Output per format

**txt** — appended sections (headers suppressed with `--no-banner`/`--quiet`):
```
api.target.com
www.target.com

# External hosts
partner.com
cdn.fastly.net

# IPs
104.21.1.1
172.67.1.1

# URLs
https://target.com/static/main.js
https://target.com/static/main.js.map
```

**json** — top-level `"extras"` object:
```json
"extras": {
  "hosts": ["cdn.fastly.net", "partner.com"],
  "ips":   ["104.21.1.1", "172.67.1.1"],
  "urls":  ["https://target.com/static/main.js"]
}
```

**ndjson** — additional lines with `type` field:
```json
{"domain": "target.com", "subdomain": "partner.com",              "type": "extra_host"}
{"domain": "target.com", "subdomain": "104.21.1.1",               "type": "extra_ip"}
{"domain": "target.com", "subdomain": "https://target.com/api/v1","type": "extra_url"}
```

**csv** — extra rows with `type` = `extra_host`, `extra_ip`, `extra_url`.

### jq recipes for extras

```bash
# External hosts only
python simplerecon.py -d target.com --sources crtsh,censys --show-extras -o ndjson \
  | jq 'select(.type == "extra_host") | .subdomain'

# IPs (combine with verify-live)
python simplerecon.py -d target.com --profile fast --verify-live --show-extras -o ndjson \
  | jq 'select(.type == "extra_ip") | .subdomain'

# All crawled JS files
python simplerecon.py -d target.com --sources spider --show-extras -o ndjson \
  | jq 'select(.type == "extra_url" and (.subdomain | endswith(".js"))) | .subdomain'
```

---

## Network Mapping — Graph JSON and HTML visualization

Turn the flat enumeration result into a navigable network topology: a JSON graph (nodes + edges) you can pipe into other tools, and an interactive HTML page for visual triage. The graph is built **entirely from data already collected** during the run — no extra requests or scans.

### Flag reference — three axes

The three flags operate independently and can be combined:

| Flag | Role | Output lands in | Combinable? |
|---|---|---|---|
| **`-o html`** | Primary output format — replaces `txt`/`json`/`csv`/`ndjson` | `stdout` or `--outfile` | One `-o` at a time |
| **`--network-html FILE`** | Side artifact — always writes the HTML visualization to `FILE` | `FILE` (any path) | Yes — works alongside any `-o` |
| **`--network-map`** | Injects a `"network"` block (nodes/edges) into the JSON output | Inside the JSON document | Only meaningful with `-o json`; auto-enabled by `-o html`/`--network-html` |

### Concrete examples

```bash
# 1) HTML only — no JSON, no txt
python simplerecon.py -d target.com --verify-live -o html --outfile map.html
# → map.html (interactive graph)

# 2) JSON enriched with the graph block
python simplerecon.py -d target.com --verify-live --network-map -o json --outfile out.json
# → out.json: {"domain":..., "subdomains":..., "live_hosts":..., "network": {nodes, edges, stats}}
#   (without --network-map the JSON does not include the "network" field)

# 3) Plain-text results + HTML map side by side
python simplerecon.py -d target.com --verify-live -o txt --outfile out.txt --network-html map.html
# → out.txt (flat subdomain list)  +  map.html (visualization)

# 4) Two artifacts in one run — JSON data + HTML for the browser
python simplerecon.py -d target.com --verify-live --network-map -o json --outfile out.json --network-html map.html
# → out.json (with network block)  +  map.html (visualization)

# 5) Multiple targets merged into one combined graph
python simplerecon.py -l targets.txt --verify-live --tld-brute -o html --outfile multi.html
```

### Graph model

| Node type | Built from | Notes |
|---|---|---|
| `domain` | scan target | one per target |
| `subdomain` | `result.subdomains` | colored by `live.status` (2xx/3xx/4xx/5xx/none) |
| `ip` | `live[sub].ips` (needs `--verify-live`) | shared across subdomains that share an IP |
| `cloud` | `live[sub].cloud` | one node per provider (AWS / Cloudflare / GCP / …) |
| `cname` | `live[sub].cname` | only when CNAME points **outside** the target zone |
| `tld_variant` | `result.tld_variants` (needs `--tld-brute`) | linked back to the root domain |

| Edge relation | Direction |
|---|---|
| `has_subdomain` | `domain → subdomain` |
| `resolves_to` | `subdomain → ip` |
| `hosted_on` | `subdomain → cloud` |
| `cname_to` | `subdomain → cname` |
| `tld_variant_of` | `tld_variant → domain` |

### JSON shape (with `--network-map`)

```json
{
  "domain": "target.com",
  "subdomains": [...],
  "live_hosts": { ... },
  "network": {
    "nodes": [
      {"id": "target.com",     "type": "domain",    "label": "target.com", "color": "#1976d2"},
      {"id": "api.target.com", "type": "subdomain", "label": "api",        "color": "#4caf50", "status": 200},
      {"id": "104.18.22.1",    "type": "ip",        "label": "104.18.22.1","color": "#00897b"},
      {"id": "cloud:cloudflare","type": "cloud",    "label": "CLOUDFLARE", "color": "#fbc02d"}
    ],
    "edges": [
      {"from": "target.com",     "to": "api.target.com", "relation": "has_subdomain"},
      {"from": "api.target.com", "to": "104.18.22.1",    "relation": "resolves_to"},
      {"from": "api.target.com", "to": "cloud:cloudflare","relation": "hosted_on"}
    ],
    "stats": {"domains": 1, "subdomains": 42, "ips": 18, "clouds": 3, "cnames": 5, "tld_variants": 2, "edges": 71}
  }
}
```

### HTML viewer

Single self-contained file. Loads [vis-network](https://visjs.github.io/vis-network/) `9.1.9` from `unpkg.com` (CDN — requires internet when opened). Features:

- Force-directed layout with zoom, pan, navigation buttons, keyboard controls
- Click a node → detail panel with HTTP status, title, server header
- Legend with per-type counts and status-color key
- All targets from a multi-target run merged into one graph

<center>

![Screenshot](/assets/screenshot/img4.png)

</center>

### jq recipes for the graph block

```bash
# Top providers across the surface
jq '.network.nodes[] | select(.type == "cloud") | .label' out.json | sort | uniq -c

# Subdomains pointing at a specific IP
jq -r --arg ip 104.18.22.1 \
  '.network.edges[] | select(.relation == "resolves_to" and .to == $ip) | .from' out.json

# CNAMEs to external services (potential third-party dependencies)
jq -r '.network.nodes[] | select(.type == "cname") | .label' out.json

# Quick summary
jq '.network.stats' out.json
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

NSEC records form a sorted linked list of every name in the DNS zone. The `nsec_walk` source traverses the chain to enumerate the entire zone without a zone transfer. Works only when the domain uses **NSEC** (not NSEC3 - the module detects and reports this automatically).

```bash
python simplerecon.py -d target.com --sources nsec_walk -v
# Example domain with NSEC: nlnetlabs.nl
```

### SRV Record Enumeration (Amass)

Queries ~70 common SRV prefixes (`_http._tcp`, `_ldap._tcp`, `_kerberos._tcp`, `_autodiscover._tcp`, `_sip._tcp`, etc.). SRV records frequently reveal internal hostnames not found through passive sources.

```bash
python simplerecon.py -d target.com --sources srv_enum -v
```

The prefix list is in `config/srv_prefixes.json` - edit it to add domain-specific services.

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

## Subdomain Takeover Detection

When `--verify-live` is enabled, each live host is checked for takeover signals via **three independent methods**:

| Method | How | Field |
|---|---|---|
| Body fingerprint | Response body matched against ~30 service signatures | `takeover` |
| CNAME chain | Full CNAME chain walked; suffix matched against 21 services | `takeover: "cname:<service>"` |
| WAF / CDN | Response headers fingerprinted against 11 providers | `waf` |

```bash
python simplerecon.py -d target.com --verify-live -o json --outfile out.json
```

```
[LIVE] orphan.target.com  → 404  - NoSuchBucket [TAKEOVER? aws-s3]
[LIVE] docs.target.com    → 404  - There isn't a GitHub Pages site here. [TAKEOVER? cname:github-pages]
[LIVE] api.target.com     → 200  - API Gateway [cloudflare]
```

**Takeover-detectable services (body + CNAME):**

`aws-s3`, `github-pages`, `heroku`, `netlify`, `fastly`, `shopify`, `ghost-io`, `surge-sh`, `zendesk`, `readme-io`, `unbounce`, `webflow`, `squarespace`, `hubspot`, `freshdesk`, `sendgrid`, `uservoice`, `wpengine`, `pantheon`, `teamwork`, `acquia`, `bigcartel`

**WAF / CDN fingerprinting:**

`cloudflare`, `akamai`, `fastly`, `cloudfront`, `incapsula`, `sucuri`, `azure-cdn`, `google`, `imperva`, `barracuda`, `f5-big-ip`

All fingerprints are defined in [verify/live_check.py](verify/live_check.py) (`_TAKEOVER_CNAME`, `_TAKEOVER_BODY`, `_WAF_HEADERS`) - edit there to add new services.

> **Note:** A positive match is a **candidate**, not a confirmed takeover. Always verify CNAME ownership before claiming.

### jq recipes for takeover triage

```bash
python simplerecon.py -d target.com --verify-live -o ndjson \
  | jq 'select(.takeover != null)'

# Only CNAME-based hits
python simplerecon.py -d target.com --verify-live -o ndjson \
  | jq 'select(.takeover | strings | startswith("cname:"))'

# Show WAF-protected hosts
python simplerecon.py -d target.com --verify-live -o ndjson \
  | jq 'select(.waf != null) | {subdomain, waf, status}'

# JSON outfile - extract takeover candidates
jq -r '.live_hosts | to_entries[] | select(.value.takeover != null) | .key' out.json \
  | dnsx -silent -cname -resp
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
      "ips": ["104.18.22.1", "104.18.23.1"],
      "cloud": "cloudflare",
      "tls_sans": ["api.target.com", "*.api.target.com", "cdn.target.com"],
      "cname": null,
      "waf": "cloudflare",
      "takeover": null
    },
    "orphan.target.com": {
      "status": 404,
      "title": "",
      "server": "AmazonS3",
      "content_length": 320,
      "url": "https://orphan.target.com",
      "ips": ["52.217.33.142"],
      "cloud": "aws",
      "tls_sans": [],
      "cname": "orphan.target.com.s3-website-us-east-1.amazonaws.com",
      "waf": null,
      "takeover": "cname:aws-s3"
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
domain,subdomain,type,status,title,server,ips,cloud,tls_sans,takeover,cname,waf
target.com,api.target.com,subdomain,200,API Gateway,nginx/1.24.0,104.18.22.1|104.18.23.1,cloudflare,api.target.com|*.api.target.com,,,cloudflare
target.com,mail.target.com,subdomain,200,Webmail,Apache/2.4,203.0.113.5,,,,
target.com,orphan.target.com,subdomain,404,,AmazonS3,52.217.33.142,aws,,cname:aws-s3,orphan.target.com.s3-website-us-east-1.amazonaws.com,
target.com,target.net,tld_variant,,,,,,,,,,
```

### NDJSON

One compact JSON line per subdomain - designed for streaming and `jq` piping.

```bash
python simplerecon.py -d target.com --verify-live -o ndjson
python simplerecon.py -d target.com --verify-live -o ndjson --outfile results/target.ndjson
```

```json
{"domain": "target.com", "subdomain": "api.target.com", "type": "subdomain", "status": 200, "title": "API Gateway", "server": "nginx/1.24.0", "ips": ["104.18.22.1"], "cloud": "cloudflare", "waf": "cloudflare"}
{"domain": "target.com", "subdomain": "orphan.target.com", "type": "subdomain", "status": 404, "server": "AmazonS3", "ips": ["52.217.33.142"], "cloud": "aws", "cname": "orphan.target.com.s3-website-us-east-1.amazonaws.com", "takeover": "cname:aws-s3"}
{"domain": "target.com", "subdomain": "dev.target.com", "type": "subdomain"}
{"domain": "target.com", "subdomain": "target.net", "type": "tld_variant"}
```

**jq examples:**

```bash
# Live hosts only
python simplerecon.py -d target.com --verify-live -o ndjson | jq 'select(.status != null)'

# Takeover candidates
python simplerecon.py -d target.com --verify-live -o ndjson | jq 'select(.takeover != null)'

# WAF-protected hosts
python simplerecon.py -d target.com --verify-live -o ndjson | jq 'select(.waf != null) | {subdomain, waf}'

# Extract only subdomains (pipe-friendly)
python simplerecon.py -d target.com -o ndjson | jq -r '.subdomain'
```

### TXT

```bash
python simplerecon.py -d target.com -o txt --outfile results/target.txt
```

### HTML — Interactive network map

```bash
python simplerecon.py -d target.com --verify-live -o html --outfile results/target.html
```

Generates a self-contained HTML page that renders the discovered topology as an interactive graph (nodes: domain / subdomain / IP / cloud / CNAME / TLD variant — edges: `has_subdomain`, `resolves_to`, `hosted_on`, `cname_to`, `tld_variant_of`). Loads [vis-network](https://visjs.github.io/vis-network/) from a CDN, so it needs internet access when opened. Subdomain nodes are colored by HTTP status (green 2xx, orange 3xx, red 4xx, purple 5xx, gray unreachable). See [Network Mapping](#network-mapping--graph-json-and-html-visualization) for details.

### Markdown — Human-readable reconnaissance report

```bash
python simplerecon.py -d target.com --verify-live -o markdown --outfile report.md
```

Generates a structured Markdown document with summary metrics, tables of live hosts, takeover candidates, duplicate body hashes, all subdomains, TLD variants, source contributions, and extras — ready to paste into GitHub issues, wikis, or deliver to clients. See [Markdown Report](#markdown-report) for details.

---

## Markdown Report

`-o markdown` produces a complete reconnaissance report as a single `.md` file.

```bash
# Markdown as primary output
python simplerecon.py -d target.com --verify-live -o markdown --outfile report.md

# Pipe to a terminal Markdown viewer
python simplerecon.py -d target.com --verify-live -o markdown | glow -
```

### Sections included

| Section | Appears when |
|---------|-------------|
| Header (date, sources, totals) | Always |
| Summary metrics table | Always |
| ⚠ Takeover Candidates | Any `takeover` detected by `--verify-live` |
| Live Hosts table (status, title, server, cloud, WAF, ms) | `--verify-live` |
| Duplicate Body Hashes | ≥2 hosts share the same response hash |
| All Subdomains (code block) | Always |
| TLD Variants | `--tld-brute` |
| Extras (hosts, IPs, URLs) | `--show-extras` |
| Source Contributions | Always |

The `duplicate_bodies` section flags hosts that returned identical response content — a reliable signal of wildcard DNS or CDN farms that weren't caught by the wildcard filter.

---

## Advanced Usage

### IP and Cloud Provider Detection

When `--verify-live` is enabled, each live host is also resolved to its IP addresses and the cloud provider is fingerprinted — both fields appear in all output formats.

```bash
python simplerecon.py -d target.com --verify-live -o json --outfile out.json
```

Detection order:
1. **CNAME chain** — matched against known provider suffixes (`*.amazonaws.com`, `*.azurewebsites.net`, `*.run.app`, etc.)
2. **IP CIDR ranges** — IP addresses matched against published ranges for AWS, Azure, GCP, Cloudflare, Fastly

Detected providers: `aws`, `azure`, `gcp`, `cloudflare`, `fastly`, `github`, `heroku`, `netlify`, `vercel`, `digitalocean`

```bash
# jq — show IPs and cloud per live host
jq '.live_hosts | to_entries[] | {host: .key, ips: .value.ips, cloud: .value.cloud}' out.json

# ndjson — filter only AWS-hosted subdomains
python simplerecon.py -d target.com --verify-live -o ndjson | jq 'select(.cloud == "aws")'
```

### Proxy support

Route **all** HTTP requests (passive sources, active sources, `--verify-live`) through a proxy (Burp, mitmproxy, SOCKS5):

```bash
# HTTP/S proxy (e.g. Burp Suite)
python simplerecon.py -d target.com --proxy http://127.0.0.1:8080

# SOCKS5 proxy (e.g. Tor)
python simplerecon.py -d target.com --proxy socks5://127.0.0.1:9050
```

### Custom User-Agent

```bash
python simplerecon.py -d target.com --user-agent 'Mozilla/5.0 (compatible; MyScanner/1.0)'
```

### Excluding sources

```bash
# Run everything except noisy/slow sources
python simplerecon.py -d target.com --exclude github,intelx,publicwww

# Profile with overrides
python simplerecon.py -d target.com --profile osint --exclude merklemap,chaos
```

### Stdin / pipe targets

```bash
# Explicit flag
echo 'target.com' | python simplerecon.py --stdin -o ndjson

# Auto-detected when stdin is not a TTY
cat domains.txt | python simplerecon.py -o txt

# Chain with amass, subfinder, or other tools
subfinder -silent -d target.com | python simplerecon.py --stdin --sources crtsh,virustotal
```

### httpx - HTTP probing

```bash
python simplerecon.py -d target.com --no-banner | httpx -silent -status-code -title -tech-detect

# Filter only 200 OK
python simplerecon.py -d target.com --no-banner | httpx -silent -mc 200
```

### nmap - port scan

```bash
python simplerecon.py -d target.com -o txt --outfile subs.txt
nmap -iL subs.txt -p 80,443,8080,8443 -T4 --open
```

### nuclei - vulnerability scanning

```bash
python simplerecon.py -d target.com --no-banner \
  | httpx -silent \
  | nuclei -t cves/ -silent
```

### dnsx - DNS resolution and CNAME chasing

```bash
# Find potential subdomain takeovers
python simplerecon.py -d target.com --no-banner \
  | dnsx -silent -cname -resp \
  | grep -E 'amazonaws|azurewebsites|github.io|herokuapp'
```

### eyewitness - screenshots

```bash
python simplerecon.py -d target.com --verify-live -o txt --outfile subs.txt
eyewitness --web -f subs.txt --no-prompt -d screenshots/
```

### SimpleReconSubdomain - enrichment and automation

[SimpleReconSubdomain](https://github.com/MrCl0wnLab/SimpleReconSubdomain) (`String-x (aka strx)`) is a modular automation tool using a `{STRING}` placeholder. It pairs naturally with SimpleReconSubdomain via pipes.

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

All sources inherit from `BaseSource` in `sources/base.py`. Drop the file in `sources/passive/` or `sources/active/` - no other file needs editing.

The class name must be the **title-cased filename** (e.g. `myservice.py` → class `Myservice`), and `NAME` must equal the filename without `.py`.

### New Passive Source

```python
# sources/passive/myservice.py
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
        headers = {'Authorization': f'Bearer {api_key}'}
        async with self._make_client(headers=headers) as client:
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
