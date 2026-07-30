"""SSRF guard for any transport that dials a peer-advertised URL.

Every outbound HTTP path in AMP shares one hazard: the URL comes from a card
the *counterparty* published, so a malicious card can point it at
``127.0.0.1``, cloud metadata, or an internal admin API and turn this node
into an SSRF proxy into its own network. A card's signature proves who
published it — never that the URL it carries is safe to dial.

Checking the URL once is not enough: redirects and DNS rebinding both defeat
a pre-flight check. So this module provides the whole defence as a unit —
shape validation without DNS, an ``is_global`` address check that also
unwraps the IPv6 forms carrying a routable IPv4 (NAT64/6to4/Teredo/mapped),
a resolver that re-applies the check at connection time (closing the
rebinding window), and redirect-free delivery. The wake path and the direct
HTTP transport share it so neither can drift from the other.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


class SsrfError(Exception):
    """A URL was refused as unsafe to dial (bad shape or non-public host)."""


# IPv6 forms that embed a routable IPv4 address. An address can look perfectly
# global while the network delivers it to whatever IPv4 it carries.
_NAT64_PREFIXES = (
    ipaddress.ip_network("64:ff9b::/96"),    # RFC 6052 well-known prefix
    ipaddress.ip_network("64:ff9b:1::/48"),  # RFC 8215 local-use prefix
)
_SIXTOFOUR_RELAY = ipaddress.ip_network("192.88.99.0/24")  # RFC 7526, deprecated


def _embedded_ipv4(ip):
    """Every IPv4 address an IPv6 address could actually reach."""
    if ip.version != 6:
        return ()
    found = []
    for attribute in ("ipv4_mapped", "sixtofour"):
        value = getattr(ip, attribute, None)
        if value is not None:
            found.append(value)
    teredo = getattr(ip, "teredo", None)
    if teredo:
        found.extend(teredo)  # (server, client)
    packed = int(ip)
    if any(ip in prefix for prefix in _NAT64_PREFIXES):
        found.append(ipaddress.IPv4Address(packed & 0xFFFFFFFF))
    if packed >> 32 == 0 and packed != 0:
        # IPv4-compatible ::a.b.c.d (deprecated, still parsed by stacks).
        found.append(ipaddress.IPv4Address(packed & 0xFFFFFFFF))
    return tuple(found)


@dataclass(frozen=True)
class SsrfPolicy:
    """What a transport is willing to dial.

    Defaults are deliberately restrictive: a node accepting cards from anyone
    is one careless default away from being an SSRF proxy into its own
    network. Two things make a naive check useless, and both are handled here
    rather than by the caller:

    - **Redirects.** Validating the first URL proves nothing if the client
      follows a 302 into ``169.254.169.254``. Guarded delivery never follows
      redirects.
    - **DNS rebinding.** Validating a hostname and then letting the HTTP
      client resolve it again is a race an attacker with a low-TTL record
      wins every time. Validation therefore happens *at connection time*,
      inside the resolver (:meth:`guarded_resolver`).
    """

    allow_private: bool = False  # loopback / RFC1918 / link-local / metadata
    allowed_schemes: frozenset[str] = field(
        default_factory=lambda: frozenset({"https"})
    )
    max_url_length: int = 2048

    def check_url_shape(self, url: str) -> str:
        """Validate everything knowable without DNS. Returns the hostname.

        When the host is a literal IP, the address check runs here too — no
        DNS is needed, so a loopback/metadata/RFC1918 literal is rejected at
        the earliest possible point rather than deferred to connect time."""
        if not url or len(url) > self.max_url_length:
            raise SsrfError("URL missing or too long")
        parsed = urlparse(url)
        if parsed.scheme not in self.allowed_schemes:
            raise SsrfError(f"scheme {parsed.scheme!r} not allowed")
        if not parsed.hostname:
            raise SsrfError("URL has no host")
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass  # a hostname — its address is checked at connect time
        else:
            self.check_address(parsed.hostname)
        return parsed.hostname

    def check_address(self, address: str) -> None:
        """Reject a resolved IP that is not publicly routable.

        Uses ``is_global`` rather than enumerating private/loopback/link-local:
        enumeration silently allowed carrier-grade NAT space (100.64.0.0/10),
        which is reachable internal network in many deployments. Multicast is
        excluded separately because ``is_global`` is True for it. Several IPv6
        forms *carry* an IPv4 address the network will actually route to
        (NAT64, 6to4, Teredo, IPv4-mapped, IPv4-compatible), so each embedded
        address is judged too.
        """
        if self.allow_private:
            return
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise SsrfError(f"unparseable address {address!r}") from exc
        for candidate in (ip, *_embedded_ipv4(ip)):
            if (
                not candidate.is_global
                or candidate.is_multicast
                or candidate in _SIXTOFOUR_RELAY
            ):
                raise SsrfError(f"host resolves to a non-public address ({ip})")

    def validate(self, url: str) -> str:
        """Best-effort pre-flight: catch bad shapes and hosts that already
        resolve privately, so a misconfigured card fails loudly and early.
        NOT the defence against rebinding — that is :meth:`check_address`
        applied at connect time via :meth:`guarded_resolver`. Returns the
        validated hostname."""
        hostname = self.check_url_shape(url)
        for address in self._resolve(hostname):
            self.check_address(address)
        return hostname

    @staticmethod
    def _resolve(hostname: str) -> list[str]:
        try:
            ipaddress.ip_address(hostname)
            return [hostname]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise SsrfError(f"host does not resolve: {hostname}") from exc
        resolved = {info[4][0] for info in infos}
        if not resolved:
            raise SsrfError(f"host does not resolve: {hostname}")
        return sorted(resolved)

    def guarded_resolver(self):
        """An aiohttp resolver that re-applies :meth:`check_address` to the
        address actually being connected to, leaving no window between the
        check and the dial. Raises ImportError without aiohttp installed."""
        import aiohttp

        policy = self

        class _GuardedResolver(aiohttp.abc.AbstractResolver):
            def __init__(self) -> None:
                self._inner = aiohttp.DefaultResolver()

            async def resolve(self, host, port=0, family=socket.AF_INET):
                hosts = await self._inner.resolve(host, port, family)
                for entry in hosts:
                    policy.check_address(entry["host"])
                return hosts

            async def close(self) -> None:
                await self._inner.close()

        return _GuardedResolver()
