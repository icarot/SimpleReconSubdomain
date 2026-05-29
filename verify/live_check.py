"""
Live host verification with TLS SAN extraction.

Inspired by Amass's active TLS certificate inspection: when a subdomain responds
on HTTPS, we extract all Subject Alternative Names (SANs) from the server's
certificate.  These SANs often reveal additional subdomains not discoverable
via passive sources.

SAN extraction uses Python's built-in ssl module (no extra dependencies).
"""

import asyncio
import ipaddress
import re
import socket
import ssl

import httpx

import core.colors as colors

# ---------------------------------------------------------------------------
# CNAME-based takeover fingerprints
# If the CNAME chain contains any of these suffixes the subdomain is a takeover
# candidate even when the HTTP response body shows a generic error page.
# ---------------------------------------------------------------------------
_TAKEOVER_CNAME: dict[str, list[str]] = {
    'aws-s3':          ['.s3.amazonaws.com', '.s3-website', '.s3-', 's3.amazon'],
    'github-pages':    ['.github.io'],
    'heroku':          ['.herokudns.com', '.herokuapp.com'],
    'netlify':         ['.netlify.app', '.netlify.com'],
    'azure':           ['.azurewebsites.net', '.cloudapp.azure.com',
                        '.trafficmanager.net', '.azureedge.net'],
    'fastly':          ['.fastly.net', '.fastlylb.net'],
    'shopify':         ['shops.myshopify.com'],
    'ghost-io':        ['.ghost.io'],
    'surge-sh':        ['.surge.sh'],
    'zendesk':         ['.zendesk.com'],
    'readme-io':       ['.readme.io', '.readmessl.com'],
    'unbounce':        ['.unbouncepages.com'],
    'webflow':         ['.webflow.io'],
    'squarespace':     ['.squarespace.com'],
    'hubspot':         ['.hs-sites.com', '.hubspot.net', '.hubspotpagebuilder.com'],
    'freshdesk':       ['.freshdesk.com'],
    'sendgrid':        ['.sendgrid.net'],
    'uservoice':       ['.uservoice.com'],
    'wpengine':        ['.wpengine.com'],
    'pantheon':        ['.pantheon.io', '.getpantheon.com'],
    'teamwork':        ['.teamwork.com'],
    'acquia':          ['.acquia-sites.com'],
    'bigcartel':       ['.bigcartel.com'],
}

# ---------------------------------------------------------------------------
# WAF / CDN fingerprints (response header based)
# ---------------------------------------------------------------------------
_WAF_HEADERS: dict[str, list[tuple[str, str]]] = {
    'cloudflare':   [('server', 'cloudflare'), ('cf-ray', '')],
    'akamai':       [('x-akamai-transformed', ''), ('x-check-cacheable', ''),
                     ('akamai-origin-hop', '')],
    'fastly':       [('x-fastly-request-id', ''), ('x-served-by', 'cache-')],
    'cloudfront':   [('x-amz-cf-id', ''), ('x-amz-cf-pop', ''), ('via', 'cloudfront')],
    'incapsula':    [('x-iinfo', ''), ('x-cdn', 'incapsula')],
    'sucuri':       [('x-sucuri-id', ''), ('x-sucuri-cache', '')],
    'azure-cdn':    [('x-azure-ref', ''), ('x-ec-custom-error', '')],
    'google':       [('x-goog-generation', ''), ('via', '1.1 google')],
    'imperva':      [('x-protected-by', 'imperva'), ('x-iinfo', '')],
    'barracuda':    [('x-barracuda-', '')],
    'f5-big-ip':    [('x-waf-status', ''), ('x-wa-info', '')],
}


# ---------------------------------------------------------------------------
# Subdomain-takeover fingerprints
# Each value is a list of lowercase body substrings. If ANY matches,
# the service is considered a takeover candidate.
# ---------------------------------------------------------------------------
_TAKEOVER_BODY: dict[str, list[str]] = {
    'aws-s3':            ['nosuchbucket', 'the specified bucket does not exist',
                          'nosuchkey'],
    'github-pages':      ["there isn't a github pages site here",
                          "for root urls (like http://example.com/) you must provide an index.html"],
    'heroku':            ['no such app', 'herokucdn.com/error-pages/no-such-app',
                          'there is no app configured at that hostname'],
    'netlify':           ['not found - request id:'],
    'fastly':            ['fastly error: unknown domain:'],
    'shopify':           ['sorry, this shop is currently unavailable',
                          'this shop is unavailable'],
    'tumblr':            ["there's nothing here.", 'whatever you were looking for doesn'],
    'ghost-io':          ['the thing you were looking for is no longer here'],
    'surge-sh':          ['project not found'],
    'bitbucket':         ['repository not found'],
    'zendesk':           ['help center closed', 'is not a valid subdomain'],
    'freshdesk':         ['may not exist, may have been removed, or the name'],
    'sendgrid':          ['the cname you entered does not point to sendgrid'],
    'squarespace':       ['no such account'],
    'hubspot':           ['domain not configured', 'does not exist in our system'],
    'readme-io':         ["project doesnt exist... yet!"],
    'campaign-monitor':  ['double check the url or'],
    'unbounce':          ['the requested url was not found on this server'],
    'webflow':           ["the page you are looking for doesn't exist"],
    'pantheon':          ['404 error unknown site!', '404 error: unknown site!'],
    'wpengine':          ["the site you were looking for couldn't be found"],
    'cargo':             ['cargocollective.com'],
    'helpjuice':         ['we could not find what you\u2019re looking for'],
    'helpscout':         ['no settings were found for this company'],
    'azure-blob':        ['<code>noresourceassociated</code>'],
    'strikingly':        ['page not found on strikingly'],
    'wordpress-com':     ['do you want to register'],
}

# Header-based fingerprints: {service: [(header_name, contains_substring)]}
_TAKEOVER_HEADERS: dict[str, list[tuple[str, str]]] = {
    'fastly':       [('x-served-by', 'cache-')],
    'github-pages': [('server', 'github.com')],
}


# ---------------------------------------------------------------------------
# Cloud provider detection — CNAME-based
# Maps CNAME suffixes to provider names (broader than takeover fingerprints).
# ---------------------------------------------------------------------------
_CLOUD_CNAME: dict[str, list[str]] = {
    'aws': [
        '.amazonaws.com', '.cloudfront.net', '.elb.amazonaws.com',
        '.execute-api.amazonaws.com', '.s3.amazonaws.com',
        '.awsglobalaccelerator.com', '.awsapprunner.com',
    ],
    'azure': [
        '.azurewebsites.net', '.cloudapp.azure.com', '.trafficmanager.net',
        '.azureedge.net', '.azurefd.net', '.azure.com', '.windows.net',
        '.azure-api.net', '.azurecontainer.io',
    ],
    'gcp': [
        '.appspot.com', '.googleapis.com', '.run.app', '.cloudfunctions.net',
        '.a.run.app', '.uc.r.appspot.com',
    ],
    'cloudflare': ['.cdn.cloudflare.net', '.cloudflare.com', '.cloudflare.net'],
    'fastly':     ['.fastly.net', '.fastlylb.net', '.global.ssl.fastly.net'],
    'github':     ['.github.io', '.github.com', '.githubusercontent.com'],
    'heroku':     ['.herokudns.com', '.herokuapp.com'],
    'netlify':    ['.netlify.app', '.netlify.com'],
    'vercel':     ['.vercel.app', '.vercel-infrastructure.com', '.now.sh'],
    'digitalocean': ['.digitaloceanspaces.com', '.ondigitalocean.app'],
}

# ---------------------------------------------------------------------------
# Cloud provider detection — IP CIDR ranges (summary; not exhaustive)
# ---------------------------------------------------------------------------
_CLOUD_CIDR: dict[str, list[str]] = {
    'aws': [
        '3.0.0.0/8', '13.32.0.0/15', '13.224.0.0/14', '15.197.128.0/17',
        '18.0.0.0/8', '34.192.0.0/10', '35.0.0.0/8', '44.192.0.0/10',
        '52.0.0.0/8', '54.0.0.0/8', '99.77.0.0/16', '104.16.0.0/13',
        '205.251.192.0/19',
    ],
    'azure': [
        '13.64.0.0/11', '20.0.0.0/8', '40.64.0.0/10', '51.0.0.0/8',
        '52.96.0.0/12', '65.52.0.0/14', '104.40.0.0/13', '137.116.0.0/14',
        '168.61.0.0/16', '191.232.0.0/13',
    ],
    'gcp': [
        '8.34.208.0/20', '8.35.192.0/20', '23.236.48.0/20', '23.251.128.0/19',
        '34.0.0.0/8', '35.184.0.0/13', '104.196.0.0/14', '107.167.160.0/19',
        '130.211.0.0/22', '146.148.0.0/17', '162.216.148.0/22',
        '172.217.0.0/16', '216.239.32.0/22',
    ],
    'cloudflare': [
        '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
        '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15',
        '172.64.0.0/13', '188.114.96.0/20', '190.93.240.0/20',
        '197.234.240.0/22', '198.41.128.0/17',
    ],
    'fastly': [
        '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24',
        '103.245.222.0/23', '151.101.0.0/16', '157.52.64.0/18',
        '167.82.0.0/17', '167.82.128.0/20', '172.111.64.0/18',
        '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16',
    ],
}

# Pre-parse CIDR networks for fast lookup
_PARSED_CIDR: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
for _provider, _cidrs in _CLOUD_CIDR.items():
    _PARSED_CIDR[_provider] = []
    for _c in _cidrs:
        try:
            _PARSED_CIDR[_provider].append(ipaddress.ip_network(_c, strict=False))
        except ValueError:
            pass


def _detect_cloud_provider(
    ips: list[str],
    cname_chain: list[str] | None = None,
) -> str | None:
    """Return cloud provider name from CNAME chain or IP addresses, or None."""
    # CNAME-based detection first (more reliable)
    if cname_chain:
        chain_str = ' '.join(cname_chain).lower()
        for provider, patterns in _CLOUD_CNAME.items():
            if any(p in chain_str for p in patterns):
                return provider

    # IP CIDR-based detection
    for ip_str in ips:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for provider, networks in _PARSED_CIDR.items():
            if any(addr in net for net in networks):
                return provider

    return None


def _resolve_ips_sync(hostname: str) -> list[str]:
    """Blocking: resolve A records for *hostname*, return list of IP strings."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        seen: dict[str, None] = {}
        for res in results:
            ip = res[4][0]
            seen[ip] = None
        return list(seen.keys())
    except Exception:
        return []


async def _resolve_ips(hostname: str, timeout: int = 5) -> list[str]:
    """Async wrapper for IP resolution."""
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _resolve_ips_sync, hostname),
            timeout=timeout,
        )
    except Exception:
        return []


def _detect_takeover(body: str, headers: dict) -> str | None:
    """Return the service name if the response matches a body/header takeover fingerprint."""
    body_lower = body.lower()
    for service, patterns in _TAKEOVER_BODY.items():
        if any(p in body_lower for p in patterns):
            return service
    for service, hdr_checks in _TAKEOVER_HEADERS.items():
        for hdr_name, hdr_sub in hdr_checks:
            if hdr_sub in headers.get(hdr_name, '').lower():
                return service
    return None


def _detect_cname_takeover(cname_chain: list[str]) -> str | None:
    """Return service name if any CNAME in the chain matches a takeover fingerprint."""
    chain_lower = ' '.join(cname_chain).lower()
    for service, suffixes in _TAKEOVER_CNAME.items():
        if any(s in chain_lower for s in suffixes):
            return service
    return None


def _detect_waf(headers: dict) -> str | None:
    """Return WAF/CDN name from response headers, or None."""
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for waf, checks in _WAF_HEADERS.items():
        for hdr, value in checks:
            if hdr in headers_lower:
                if not value or value in headers_lower[hdr]:
                    return waf
    return None


def _fetch_cname_chain_sync(hostname: str) -> list[str]:
    """Blocking: walk the CNAME chain using dnspython."""
    try:
        import dns.resolver
        chain: list[str] = []
        current = hostname
        for _ in range(10):  # guard against CNAME loops
            try:
                answer = dns.resolver.resolve(current, 'CNAME')
                target = str(answer[0].target).rstrip('.').lower()
                chain.append(target)
                current = target
            except Exception:
                break
        return chain
    except ImportError:
        return []


async def _get_cname_chain(hostname: str, timeout: int = 5) -> list[str]:
    """Async wrapper: walk CNAME chain for *hostname*."""
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_cname_chain_sync, hostname),
            timeout=timeout,
        )
    except Exception:
        return []


async def verify_live(
    subdomains: set[str],
    timeout: int = 5,
    quiet: bool = False,
    concurrency: int = 50,
    proxy: str | None = None,
) -> dict[str, dict]:
    """
    Probe each subdomain over HTTPS then HTTP.

    Returns a dict mapping subdomain → response metadata.
    Live hosts have a non-None 'status' key.
    For HTTPS hosts, 'tls_sans' contains SANs from the server certificate.
    """
    results: dict[str, dict] = {}
    semaphore = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=max(1, concurrency // 2),
    )

    client_kwargs: dict = {
        'timeout': timeout,
        'follow_redirects': True,
        'verify': False,  # intentional: recon may hit self-signed certs
        'limits': limits,
    }
    if proxy:
        client_kwargs['proxy'] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        async def check(sub: str) -> None:
            async with semaphore:
                https_ok = False
                for scheme in ('https', 'http'):
                    url = f'{scheme}://{sub}'
                    try:
                        resp = await client.get(url)
                        resp_headers = dict(resp.headers)
                        body_takeover = _detect_takeover(resp.text, resp_headers)
                        waf = _detect_waf(resp_headers)

                        entry: dict = {
                            'url': url,
                            'status': resp.status_code,
                            'title': _extract_title(resp.text),
                            'server': resp.headers.get('server', ''),
                            'content_length': len(resp.content),
                            'tls_sans': [],
                            'takeover': body_takeover,
                            'cname': None,
                            'waf': waf,
                        }

                        # CNAME chain + CNAME-based takeover detection
                        cname_chain = await _get_cname_chain(sub, timeout=timeout)
                        if cname_chain:
                            entry['cname'] = cname_chain[0]
                            cname_to = _detect_cname_takeover(cname_chain)
                            if cname_to and not entry['takeover']:
                                entry['takeover'] = f'cname:{cname_to}'

                        # Extract TLS SANs when connecting over HTTPS
                        if scheme == 'https':
                            https_ok = True
                            sans = await _get_tls_sans(sub, timeout=timeout)
                            entry['tls_sans'] = sans

                        # IP resolution + cloud provider identification
                        ips = await _resolve_ips(sub, timeout=timeout)
                        entry['ips'] = ips
                        entry['cloud'] = _detect_cloud_provider(ips, cname_chain)

                        results[sub] = entry

                        if not quiet:
                            title = entry['title']
                            title_str = f' - {title}' if title else ''
                            san_str = f' [{len(entry["tls_sans"])} SANs]' if entry['tls_sans'] else ''
                            takeover_str = f' [TAKEOVER? {entry["takeover"]}]' if entry['takeover'] else ''
                            waf_str = f' [{waf}]' if waf else ''
                            cloud_str = f' [{entry["cloud"]}]' if entry.get('cloud') else ''
                            ip_str = f' {",".join(ips[:2])}{"…" if len(ips) > 2 else ""}' if ips else ''
                            print(colors.format_msg(
                                f'[LIVE] {sub} → {resp.status_code}{title_str}{ip_str}{cloud_str}{san_str}{takeover_str}{waf_str}'
                            ))
                        return
                    except Exception:
                        if scheme == 'https':
                            https_ok = False

                if not https_ok:
                    results[sub] = {
                        'url': None, 'status': None, 'tls_sans': [],
                        'takeover': None, 'cname': None, 'waf': None,
                        'ips': [], 'cloud': None,
                    }

        await asyncio.gather(*[check(sub) for sub in subdomains])
    return results


async def _get_tls_sans(hostname: str, port: int = 443, timeout: int = 5) -> list[str]:
    """
    Open a raw TLS connection to *hostname*:*port* and extract the SANs
    from the server certificate.

    Returns a list of SAN strings (may include wildcards like *.example.com).
    Uses ssl.get_server_certificate() wrapped in an executor to stay async.
    """
    loop = asyncio.get_event_loop()
    try:
        cert_pem = await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_cert_pem, hostname, port),
            timeout=timeout,
        )
        if not cert_pem:
            return []
        return _parse_sans_from_pem(cert_pem)
    except Exception:
        return []


def _fetch_cert_pem(hostname: str, port: int) -> str:
    """Blocking: retrieve server certificate PEM via ssl."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return ''
                return ssl.DER_cert_to_PEM_cert(cert_der)
    except Exception:
        return ''


def _parse_sans_from_pem(cert_pem: str) -> list[str]:
    """
    Parse Subject Alternative Names from a PEM certificate.

    Uses ssl.PEM_cert_to_DER_cert + ssl module decode rather than cryptography
    library to avoid adding a dependency.
    """
    sans: list[str] = []
    try:
        cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
        # Use the built-in ssl decoder
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tmp_path = _der_to_temp_file(cert_der)
        try:
            decoded = ssl._ssl._test_decode_cert(tmp_path)  # type: ignore[attr-defined]
        finally:
            import os as _os
            try:
                _os.unlink(tmp_path)
            except OSError:
                pass
        for key, value in decoded.get('subjectAltName', ()):
            if key == 'DNS':
                sans.append(value.lower())
    except Exception:
        # Fallback: regex extraction from PEM text
        sans = _parse_sans_regex(cert_pem)
    return sans


def _der_to_temp_file(der_data: bytes) -> str:
    """Write DER bytes to a temp file, return path (for ssl._test_decode_cert)."""
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix='.der')
    try:
        os.write(fd, der_data)
    finally:
        os.close(fd)
    return path


def _parse_sans_regex(cert_pem: str) -> list[str]:
    """
    Fallback SAN extraction using regex on the PEM text representation.
    Works with pyOpenSSL-style string representations of certificates.
    """
    sans: list[str] = []
    # Match patterns like DNS:sub.example.com in certificate text dumps
    pattern = re.compile(r'DNS:([a-zA-Z0-9\*\.\-]+)', re.IGNORECASE)
    for m in pattern.finditer(cert_pem):
        sans.append(m.group(1).lower())
    return sans


def _extract_title(html: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:100] if match else ''
