"""
Live host verification with TLS SAN extraction.

Inspired by Amass's active TLS certificate inspection: when a subdomain responds
on HTTPS, we extract all Subject Alternative Names (SANs) from the server's
certificate.  These SANs often reveal additional subdomains not discoverable
via passive sources.

SAN extraction uses Python's built-in ssl module (no extra dependencies).
"""

import asyncio
import re
import socket
import ssl

import httpx

import core.colors as colors


async def verify_live(
    subdomains: set[str],
    timeout: int = 5,
    quiet: bool = False,
    concurrency: int = 50,
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

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,  # intentional: recon may hit self-signed certs
        limits=limits,
    ) as client:
        async def check(sub: str) -> None:
            async with semaphore:
                https_ok = False
                for scheme in ('https', 'http'):
                    url = f'{scheme}://{sub}'
                    try:
                        resp = await client.get(url)
                        entry: dict = {
                            'url': url,
                            'status': resp.status_code,
                            'title': _extract_title(resp.text),
                            'server': resp.headers.get('server', ''),
                            'content_length': len(resp.content),
                            'tls_sans': [],
                        }

                        # Extract TLS SANs when connecting over HTTPS
                        if scheme == 'https':
                            https_ok = True
                            sans = await _get_tls_sans(sub, timeout=timeout)
                            entry['tls_sans'] = sans

                        results[sub] = entry

                        if not quiet:
                            title = entry['title']
                            title_str = f' - {title}' if title else ''
                            san_str = f' [{len(entry["tls_sans"])} SANs]' if entry['tls_sans'] else ''
                            print(colors.format_msg(
                                f'[LIVE] {sub} → {resp.status_code}{title_str}{san_str}'
                            ))
                        return
                    except Exception:
                        if scheme == 'https':
                            https_ok = False

                if not https_ok:
                    results[sub] = {'url': None, 'status': None, 'tls_sans': []}

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
