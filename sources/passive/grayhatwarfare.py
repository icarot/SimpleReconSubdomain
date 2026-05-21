import re
import httpx
from sources.base import BaseSource
from core.config import get_key


# Strips cloud-provider suffixes from bucket hostnames to recover the raw name.
_CLOUD_SUFFIXES = re.compile(
    r'\.s3[.\-][a-z0-9\-]+\.amazonaws\.com$'
    r'|\.s3\.amazonaws\.com$'
    r'|\.blob\.core\.windows\.net$'
    r'|\.storage\.googleapis\.com$'
    r'|\.[a-z0-9\-]+\.digitaloceanspaces\.com$'
    r'|\.digitaloceanspaces\.com$'
    r'|\.aliyuncs\.com$',
    re.IGNORECASE,
)


class GrayHatWarfare(BaseSource):
    """
    Searches GrayHatWarfare (V2 API) for public cloud buckets whose name
    matches the target domain keyword.

    Each bucket hostname (e.g. 'api.example.com.s3-eu-west-1.amazonaws.com')
    is stripped of its cloud suffix to recover the raw bucket name.  Names
    that are valid subdomains of the target domain survive _filter() and are
    returned.  Works for AWS, Azure, GCP, DigitalOcean and Alibaba buckets.

    The V2 API requires a registered account token (grayhatwarfare_token);
    without one every request returns 0 results.
    """

    NAME = 'grayhatwarfare'
    DESCRIPTION = 'GrayHatWarfare cloud buckets'
    API_TOKEN_IS_REQUIREMENT = True

    _BASE_URL = 'https://buckets.grayhatwarfare.com/api/v2/buckets'

    async def fetch(self, domain: str) -> set[str]:
        token = get_key('grayhatwarfare_token')
        if not token:
            return set()

        headers: dict = {'Authorization': f'Bearer {token}'}
        params: dict = {'keywords': domain, 'limit': 100}

        subdomains: set[str] = set()
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, headers=headers
            ) as client:
                resp = await self._get(client, self._BASE_URL, params=params)

                if resp.status_code != 200:
                    return subdomains

                for bucket in resp.json().get('buckets', []):
                    # V2: 'bucket' is the full cloud hostname
                    hostname = bucket.get('bucket', '').strip().lower()
                    if not hostname:
                        continue

                    # Strip cloud suffix → raw bucket name (may be a subdomain)
                    candidate = _CLOUD_SUFFIXES.sub('', hostname)
                    subdomains.add(candidate)
                    subdomains.add(hostname)

        except Exception as e:
            self._log_exc(e)

        return self._filter(subdomains, domain)
