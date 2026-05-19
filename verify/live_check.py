import asyncio
import re

import httpx


async def verify_live(
    subdomains: set[str],
    timeout: int = 5,
    quiet: bool = False,
) -> dict[str, dict]:
    """
    Probe each subdomain over HTTPS then HTTP.

    Returns a dict mapping subdomain → response metadata.
    Live hosts have a non-None 'status' key.
    """
    results: dict[str, dict] = {}
    semaphore = asyncio.Semaphore(50)

    async def check(sub: str) -> None:
        async with semaphore:
            for scheme in ('https', 'http'):
                url = f'{scheme}://{sub}'
                try:
                    async with httpx.AsyncClient(
                        timeout=timeout,
                        follow_redirects=True,
                        verify=False,  # intentional: recon may hit self-signed certs
                    ) as client:
                        resp = await client.get(url)
                        results[sub] = {
                            'url': url,
                            'status': resp.status_code,
                            'title': _extract_title(resp.text),
                            'server': resp.headers.get('server', ''),
                            'content_length': len(resp.content),
                        }
                        if not quiet:
                            title = results[sub]['title']
                            title_str = f' - {title}' if title else ''
                            print(f'  [LIVE] {sub} → {resp.status_code}{title_str}')
                        return
                except Exception:
                    pass
            results[sub] = {'url': None, 'status': None}

    await asyncio.gather(*[check(sub) for sub in subdomains])
    return results


def _extract_title(html: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:100] if match else ''
