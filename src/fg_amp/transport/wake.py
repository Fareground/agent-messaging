"""Waking agents that are not currently connected.

AMP delivery is pull-based: a recipient holds a long-poll against the relay and
receives whatever is waiting. That works only while the recipient is running.
An agent that is asleep — the normal state for anything not kept hot — has mail
sitting in its mailbox and no idea it exists.

A **wake notification** closes that gap. A participant advertises a
``wake`` endpoint in its signed card; when the relay accepts mail for an
address with nobody listening, it POSTs a content-free ping to that URL. The
ping carries no sender, no message id, no metadata — only "there is mail,
connect and pull". Everything meaningful stays end-to-end encrypted, and the
relay learns nothing it did not already know.

Two properties make this safe to run on a public relay:

**The wake URL is attacker-influenced.** It comes from a card the agent
published, so a malicious card can point it at ``127.0.0.1`` or cloud metadata
and turn the relay into an SSRF proxy. Checking the URL once is not enough:
redirects and DNS rebinding both defeat it. So pings never follow redirects,
and the address check runs *inside the resolver* at connection time, leaving no
window between what was validated and what is dialled.

**Waking must not amplify.** The debounce is keyed on the wake **host**, not on
the recipient address — addresses are free to mint, so per-address debouncing
would let one attacker point N cards at a single victim URL and land N pings on
it. Pings are dropped rather than queued once the concurrency cap is reached,
so a flood cannot park unbounded work on the event loop, and the debounce map
is LRU-bounded so it is not a memory vector itself.

A wake is a hint, not a delivery guarantee: the poll loop is still the source of
truth, so a dropped ping costs latency, never correctness.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from collections import OrderedDict
from urllib.parse import urlparse

from .ssrf import SsrfError, SsrfPolicy

logger = logging.getLogger(__name__)

WAKE_ENDPOINT = "wake"

DEFAULT_DEBOUNCE_SECONDS = 30.0
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_CONCURRENCY = 32
# Debounce state is per wake host and LRU-bounded, so the map cannot itself be
# grown without limit by an attacker minting hosts.
DEFAULT_MAX_TRACKED = 65_536


class WakeError(SsrfError):
    """A wake target was refused, or the ping could not be delivered.

    Subclasses :class:`~fg_amp.transport.ssrf.SsrfError` so the shared SSRF
    guard's rejections surface as ``WakeError`` to existing callers while the
    address/rebinding logic lives in exactly one place (:mod:`.ssrf`)."""


class WakePolicy(SsrfPolicy):
    """What the relay is willing to send a wake ping to — the shared
    :class:`SsrfPolicy` (https-only, no private/loopback/metadata, embedded
    IPv4 unwrapped, connect-time rebinding guard), specialized only in that
    its refusals are :class:`WakeError`. See :mod:`fg_amp.transport.ssrf` for
    the guard itself."""

    def check_url_shape(self, url: str) -> str:
        try:
            return super().check_url_shape(url)
        except SsrfError as exc:
            raise WakeError(str(exc)) from exc

    def check_address(self, address: str) -> None:
        try:
            super().check_address(address)
        except SsrfError as exc:
            raise WakeError(str(exc)) from exc

    def validate(self, url: str) -> str:
        try:
            return super().validate(url)
        except SsrfError as exc:
            raise WakeError(str(exc)) from exc


class WakeNotifier:
    """Fires content-free wake pings, debounced per address.

    ``http_post`` is injectable for tests and for relays that already own an
    HTTP client; the default uses aiohttp and is imported lazily so the relay
    keeps working without it (wake simply becomes a no-op that logs).
    """

    def __init__(
        self,
        policy: WakePolicy | None = None,
        http_post=None,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        max_tracked: int = DEFAULT_MAX_TRACKED,
        clock=time.monotonic,
    ) -> None:
        self.policy = policy or WakePolicy()
        self._http_post = http_post
        self._debounce = debounce_seconds
        self._timeout = timeout_seconds
        self._max_concurrency = max_concurrency
        self._max_tracked = max_tracked
        self._clock = clock
        # Keyed by wake HOST, not by recipient address. Addresses are free to
        # mint, so debouncing per address let an attacker point N cards at one
        # victim URL and get N pings through — the debounce was protecting the
        # wrong party. LRU-bounded so the map itself is not a memory vector.
        self._last_sent: OrderedDict[str, float] = OrderedDict()
        self._inflight = 0
        self._tasks: set[asyncio.Task] = set()

    # -- policy ------------------------------------------------------------

    def wake_url(self, card: dict | None) -> str | None:
        """The wake endpoint a registered card advertises, if any."""
        if not card:
            return None
        endpoints = card.get("endpoints")
        if not isinstance(endpoints, dict):
            return None
        url = endpoints.get(WAKE_ENDPOINT)
        return url if isinstance(url, str) and url else None

    @staticmethod
    def _host_of(url: str) -> str:
        return (urlparse(url).hostname or url).lower()

    def should_send(self, url: str, now: float | None = None) -> bool:
        """False while inside the debounce window for this URL's host."""
        now = self._clock() if now is None else now
        last = self._last_sent.get(self._host_of(url))
        return last is None or (now - last) >= self._debounce

    def _record_sent(self, url: str) -> None:
        """Note that this host was just pinged, if there is room to track it.

        A host already being tracked is always refreshed. A *new* host is only
        admitted if the map has room after reclaiming expired entries — it is
        never allowed to displace a live one. Evicting the oldest live entry
        (plain LRU) is precisely what an attacker churns for: the victim's
        entry is the oldest, so cycling throwaway hosts through the cap would
        push it out and win another ping. Refusing admission instead means a
        tracked host cannot be un-tracked by anyone else's traffic.
        """
        host = self._host_of(url)
        now = self._clock()
        if host in self._last_sent:
            self._last_sent[host] = now
            self._last_sent.move_to_end(host)
            return

        self._reclaim_expired(now)
        if len(self._last_sent) >= self._max_tracked:
            logger.warning(
                "wake debounce table is full of live entries; %s is untracked "
                "this window", host)
            return
        self._last_sent[host] = now

    def _reclaim_expired(self, now: float) -> None:
        """Drop entries whose debounce window has already elapsed."""
        for host in [
            host for host, sent in self._last_sent.items()
            if (now - sent) >= self._debounce
        ]:
            del self._last_sent[host]

    # -- firing ------------------------------------------------------------

    def schedule(self, address: str, card: dict | None) -> asyncio.Task | None:
        """Fire a wake ping in the background. Never raises, never blocks.

        Returns the task (for tests); None when no ping was warranted.
        """
        url = self.wake_url(card)
        if url is None or not self.should_send(url):
            return None
        # Drop rather than queue when saturated. Creating a task per message
        # and letting a semaphore serialize them bounds sockets but not tasks,
        # so a flood still parks unbounded pending work on the loop.
        if self._inflight >= self._max_concurrency:
            logger.warning("wake queue saturated; dropping ping for %s", address)
            return None
        self._record_sent(url)
        try:
            task = asyncio.get_running_loop().create_task(self._send(address, url))
        except RuntimeError:  # no running loop — nothing to schedule onto
            return None
        self._inflight += 1
        self._tasks.add(task)

        def _done(t: asyncio.Task) -> None:
            self._inflight -= 1
            self._tasks.discard(t)

        task.add_done_callback(_done)
        return task

    async def _send(self, address: str, url: str) -> None:
        try:
            # Pre-flight. Not sufficient on its own — a rebinding attacker can
            # answer this lookup honestly and the next one differently — but it
            # rejects obviously-bad targets before opening a socket, and it is
            # the only check that applies when a caller injects its own HTTP
            # client (which then owns connect-time safety itself).
            self.policy.validate(url)
        except WakeError as exc:
            # A bad wake URL is the agent's problem, not the relay's. Log and
            # move on; the agent's poll loop still delivers its mail.
            logger.warning("refusing wake for %s: %s", address, exc)
            return
        try:
            await asyncio.wait_for(self._post(url), self._timeout)
        except Exception as exc:  # noqa: BLE001 — wake is best-effort by design
            logger.info("wake ping to %s failed: %s", address, exc)

    async def _post(self, url: str) -> None:
        # Content-free by construction: an empty JSON object and nothing else.
        # Adding sender or message details here would leak metadata the relay
        # is otherwise careful never to expose.
        if self._http_post is not None:
            await self._http_post(url, {})
            return
        await self._aiohttp_post(url, {}, self.policy)

    @staticmethod
    async def _aiohttp_post(url: str, body: dict, policy: WakePolicy) -> None:
        try:
            import aiohttp
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise WakeError("aiohttp is required for wake notifications") from exc

        class _GuardedResolver(aiohttp.abc.AbstractResolver):
            """Applies the policy to the address actually being connected to.

            Validating a URL and then letting the client resolve the hostname
            again leaves a window an attacker with a low-TTL record wins every
            time. Checking inside the resolver closes it: there is no second
            lookup between the check and the connection.
            """

            def __init__(self) -> None:
                self._inner = aiohttp.DefaultResolver()

            async def resolve(self, host, port=0, family=socket.AF_INET):
                hosts = await self._inner.resolve(host, port, family)
                for entry in hosts:
                    policy.check_address(entry["host"])
                return hosts

            async def close(self) -> None:
                await self._inner.close()

        connector = aiohttp.TCPConnector(resolver=_GuardedResolver())
        async with aiohttp.ClientSession(connector=connector) as session:
            # allow_redirects=False: a wake has no legitimate reason to
            # redirect, and following one would re-open every SSRF path the
            # policy just closed.
            async with session.post(url, json=body, allow_redirects=False) as response:
                await response.read()

    async def drain(self) -> None:
        """Await in-flight pings. For tests and orderly shutdown."""
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
