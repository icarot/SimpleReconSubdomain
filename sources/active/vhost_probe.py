"""
Virtual host probing (vhost enum).

Resolves the target domain to its A records, then sends HTTP requests with
varying Host headers to each IP. A response that differs from the baseline
(different status code or significantly different body size) indicates a
real virtual host — i.e. an unlisted subdomain running on the same server.

Wordlist is built-in (common dev/staging/infra labels). Pass a custom
wordlist via future extension.

No API key required; makes direct TCP connections to target IPs.
"""
import asyncio
import socket

import httpx

from sources.base import BaseSource

_VHOST_WORDS = [
    # Dev / staging / test environments
    'dev', 'dev1', 'dev2', 'dev3', 'development',
    'staging', 'stage', 'stg', 'stg1',
    'test', 'test1', 'test2', 'testing',
    'qa', 'qa1', 'qa2', 'uat', 'sit',
    'preprod', 'pre-prod', 'pre', 'rc',
    'sandbox', 'playground', 'lab', 'labs',
    'demo', 'preview', 'beta', 'alpha', 'canary',
    # Production / infra
    'prod', 'production', 'live', 'www', 'web', 'app', 'apps',
    'api', 'api2', 'apiv2', 'v1', 'v2',
    'cdn', 'static', 'assets', 'media', 'img', 'images',
    'files', 'uploads', 'download', 'downloads', 's3', 'storage',
    # Admin / management
    'admin', 'administrator', 'admin1', 'panel', 'control',
    'dashboard', 'cp', 'cpanel', 'whm', 'plesk',
    'mgmt', 'management', 'manage', 'manager',
    'portal', 'console', 'ui', 'gui',
    # Internal / network
    'internal', 'intranet', 'corp', 'corporate', 'private',
    'vpn', 'remote', 'gateway', 'proxy', 'firewall', 'fw',
    'ns', 'ns1', 'ns2', 'dns', 'mx', 'smtp',
    'mail', 'mail1', 'mail2', 'webmail', 'imap', 'pop', 'exchange',
    # DevOps / CI-CD
    'jenkins', 'ci', 'cd', 'build', 'deploy', 'deployment',
    'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo',
    'registry', 'docker', 'k8s', 'kubernetes', 'rancher', 'nomad',
    'vault', 'consul', 'terraform', 'ansible', 'puppet', 'chef',
    # Observability / monitoring
    'monitor', 'monitoring', 'grafana', 'kibana', 'prometheus',
    'elk', 'logstash', 'splunk', 'datadog', 'newrelic',
    'alert', 'alerts', 'status', 'uptime', 'health',
    # Auth / identity
    'auth', 'sso', 'login', 'oauth', 'oidc', 'idp', 'identity', 'accounts',
    # Support / customer-facing
    'support', 'help', 'helpdesk', 'ticket', 'tickets', 'jira',
    'docs', 'doc', 'wiki', 'kb', 'knowledge',
    'forum', 'community', 'chat', 'slack', 'feedback',
    # Backend services
    'backend', 'frontend', 'service', 'services', 'svc',
    'rpc', 'graphql', 'grpc', 'ws', 'websocket',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
    'search', 'elastic', 'solr',
    # Security / scanning
    'waf', 'security', 'sec', 'scan', 'pentest', 'bug',
    # Analytics / marketing
    'analytics', 'metrics', 'stats', 'tracking',
    'ads', 'marketing', 'campaign', 'email', 'newsletter',
    'shop', 'store', 'checkout', 'payment', 'pay',
]

_CONCURRENCY = 20
_CONTENT_DIFF_THRESHOLD = 200  # bytes


class VhostProbe(BaseSource):
    NAME = 'vhost_probe'
    DESCRIPTION = 'Active: virtual host probing — Host-header brute-force on target IPs'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()

        # Resolve target IPs
        try:
            _, _, ips = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname_ex, domain),
                timeout=10,
            )
        except Exception:
            return set()

        if not ips:
            return set()

        # Deduplicate IPs (gethostbyname_ex can return duplicates)
        ips = list(dict.fromkeys(ips))

        # Establish a baseline response for the main domain on the first IP
        baseline_status: int | None = None
        baseline_length: int | None = None
        try:
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                resp = await client.get(
                    f'http://{ips[0]}',
                    headers={'Host': domain},
                    follow_redirects=False,
                )
                baseline_status = resp.status_code
                baseline_length = len(resp.content)
        except Exception:
            pass  # If baseline fails, still attempt probing

        subdomains: set[str] = set()
        sem = asyncio.Semaphore(_CONCURRENCY)

        async def probe(ip: str, candidate: str) -> None:
            host = f'{candidate}.{domain}'
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=5, verify=False) as client:
                        resp = await client.get(
                            f'http://{ip}',
                            headers={'Host': host},
                            follow_redirects=False,
                        )
                        status_diff = resp.status_code != baseline_status
                        length_diff = abs(len(resp.content) - (baseline_length or 0)) > _CONTENT_DIFF_THRESHOLD
                        if status_diff or length_diff:
                            subdomains.add(host)
                            self._vlog(
                                1,
                                f'vhost hit: {host} on {ip} '
                                f'({resp.status_code}, {len(resp.content)}B)',
                            )
                except Exception:
                    pass

        tasks = [probe(ip, word) for ip in ips for word in _VHOST_WORDS]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._filter(subdomains, domain)
