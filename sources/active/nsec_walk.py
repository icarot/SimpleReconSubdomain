# -*- coding: utf-8 -*-
"""
DNSSEC NSEC Zone Walking (active source).

Exploits DNSSEC NSEC (Next Secure) records to enumerate an entire DNS zone.
NSEC records form a sorted linked list: each record reveals the next name in the
zone, allowing the complete zone to be traversed without a zone transfer.

This technique (described by Amass and OWASP) works when:
  1. The domain has DNSSEC enabled
  2. The zone uses NSEC (not NSEC3) — NSEC3 uses hashed names, blocking enumeration

Detection level: HIGH — sends DNS queries directly to authoritative nameservers.

Reference:
  https://www.pentestpartners.com/security-blog/dnssec-nsec-the-accidental-treasure-map-to-your-subdomains/
"""

import asyncio

import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from sources.base import BaseSource

_MAX_ITERATIONS = 2000  # safety cap to prevent infinite loops
_QUERY_TIMEOUT = 3.0    # per-query DNS UDP timeout (seconds)


class Nsec_walk(BaseSource):
    NAME = 'nsec_walk'
    DESCRIPTION = 'Active: DNSSEC NSEC zone walking to enumerate DNS zone entries'
    API_TOKEN_IS_REQUIREMENT = False

    async def fetch(self, domain: str) -> set[str]:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._run, domain),
                timeout=max(self.timeout, 30),
            )
        except asyncio.TimeoutError:
            self._vlog(1, f'timed out after {self.timeout}s')
            return set()

    def _run(self, domain: str) -> set[str]:
        subdomains: set[str] = set()

        # Step 1: Resolve the authoritative nameservers for the domain
        nameservers = self._get_nameservers(domain)
        if not nameservers:
            self._vlog(1, f'could not resolve NS records for {domain}')
            return set()

        self._vlog(2, f'nameservers: {nameservers}')

        # Step 2: Check if NSEC is available (vs NSEC3)
        ns_ip = nameservers[0]
        nsec_type = self._detect_nsec_type(domain, ns_ip)

        if nsec_type == 'NSEC3':
            self._vlog(1, f'{domain} uses NSEC3 (hashed) — zone walking not possible')
            return set()
        if nsec_type is None:
            self._vlog(1, f'{domain} does not have DNSSEC/NSEC enabled')
            return set()

        self._vlog(1, f'{domain} uses NSEC — starting zone walk')

        # Step 3: Walk the NSEC chain
        current = domain
        iterations = 0

        while iterations < _MAX_ITERATIONS:
            iterations += 1
            next_name, names_in_record = self._query_nsec(current, ns_ip, domain)

            for name in names_in_record:
                if name and (name == domain or name.endswith(f'.{domain}')):
                    subdomains.add(name.lower())

            if next_name is None:
                break

            # Normalize next name
            next_norm = next_name.lower().rstrip('.')

            # Zone walk complete when we wrap around to the start
            if next_norm == domain or next_norm in ('', '.'):
                break

            # Detect loops
            if next_norm == current.lower():
                break

            current = next_name

        self._vlog(1, f'zone walk completed in {iterations} iterations, found {len(subdomains)} names')
        return self._filter(subdomains, domain)

    def _get_nameservers(self, domain: str) -> list[str]:
        """Return a list of IP addresses for the authoritative NSes of *domain*."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = _QUERY_TIMEOUT
        resolver.lifetime = _QUERY_TIMEOUT
        ips: list[str] = []
        try:
            ns_answers = resolver.resolve(domain, 'NS')
            for rdata in ns_answers:
                ns_name = str(rdata.target).rstrip('.')
                try:
                    a_answers = resolver.resolve(ns_name, 'A')
                    for a_rdata in a_answers:
                        ips.append(str(a_rdata.address))
                except Exception:
                    pass
        except Exception as exc:
            self._log_exc(exc)
        return ips

    def _detect_nsec_type(self, domain: str, ns_ip: str) -> str | None:
        """
        Return 'NSEC', 'NSEC3', or None.

        Queries the SOA record with DNSSEC DO bit; inspects the authority section
        for NSEC or NSEC3 records to determine which variant is in use.
        """
        try:
            qname = dns.name.from_text(domain)
            request = dns.message.make_query(qname, dns.rdatatype.SOA, want_dnssec=True)
            response = dns.query.udp(request, ns_ip, timeout=_QUERY_TIMEOUT)

            for rrset in response.answer + response.authority:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    return 'NSEC'
                if rrset.rdtype == dns.rdatatype.NSEC3:
                    return 'NSEC3'
                if rrset.rdtype == dns.rdatatype.NSEC3PARAM:
                    return 'NSEC3'

            # Try a direct NSEC query
            request2 = dns.message.make_query(qname, dns.rdatatype.NSEC, want_dnssec=True)
            response2 = dns.query.udp(request2, ns_ip, timeout=_QUERY_TIMEOUT)
            for rrset in response2.answer + response2.authority:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    return 'NSEC'
                if rrset.rdtype in (dns.rdatatype.NSEC3, dns.rdatatype.NSEC3PARAM):
                    return 'NSEC3'

        except Exception as exc:
            self._log_exc(exc)
        return None

    def _query_nsec(
        self, name: str, ns_ip: str, domain: str
    ) -> tuple[str | None, set[str]]:
        """
        Query for NSEC record at *name*.

        Returns:
            (next_name, names_in_this_record)
            next_name is None when the chain cannot be continued.
        """
        names: set[str] = set()
        next_name: str | None = None

        try:
            qname = dns.name.from_text(name if name.endswith('.') else name + '.')
            request = dns.message.make_query(qname, dns.rdatatype.NSEC, want_dnssec=True)
            response = dns.query.udp(request, ns_ip, timeout=_QUERY_TIMEOUT)

            for rrset in response.answer + response.authority:
                if rrset.rdtype != dns.rdatatype.NSEC:
                    continue
                # The owner name of the NSEC record is itself a valid zone name
                owner = str(rrset.name).rstrip('.').lower()
                if owner and (owner == domain or owner.endswith(f'.{domain}')):
                    names.add(owner)

                for rdata in rrset:
                    # rdata.next is the next name in the sorted zone order
                    nxt = str(rdata.next).rstrip('.').lower()
                    if nxt:
                        next_name = nxt
                        if nxt == domain or nxt.endswith(f'.{domain}'):
                            names.add(nxt)

        except Exception as exc:
            self._log_exc(exc)

        return next_name, names
