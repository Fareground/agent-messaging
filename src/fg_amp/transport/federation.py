"""Federation-lite (SPEC §13.3): relays sync directories, never mailboxes.

A ``RelaySyncer`` pulls another relay's card directory and revocation lists
through the same public ``?since=`` delta endpoints every client uses, and
admits each record into the local store only after running it through the
exact verification the local POST/PUT endpoints apply (signature against the
self-certifying address). A hostile or corrupted record is skipped and
counted, never admitted — the peer relay is as untrusted as any client.

What deliberately does NOT federate: mailboxes. An envelope enqueued at relay
A exists only at relay A; a participant reachable there must be messaged
there (its signed card says which relays those are). Forwarding mail between
relays would turn every peered relay into a delivery path the recipient never
consented to, and would break the single-mailbox lease/ack model.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..identity.card import AgentCard
from ..identity.delegation import KeyRevocation, Revocation
from .relay import (
    CARDS_PATH,
    KEY_REVOCATIONS_PATH,
    REVOCATIONS_PATH,
    RelayState,
)

logger = logging.getLogger(__name__)

DEFAULT_SYNC_INTERVAL_SECONDS = 30.0


class RelaySyncer:
    """Periodically pulls one peer relay's directory deltas into local state.

    One syncer per peer; each keeps its own cursors, so every sync round
    transfers only what changed since the last. ``http_call`` is injectable
    for tests; the default uses aiohttp (the relay's existing HTTP stack).
    """

    def __init__(self, state: RelayState, peer_url: str, http_call: Any = None):
        self._state = state
        self._peer = peer_url.rstrip("/")
        self._http_call = http_call or self._aiohttp_call
        self._session = None  # aiohttp session, lazily created
        self._cards_cursor = 0
        self._rev_cursor = 0
        self._key_rev_cursor = 0

    @property
    def peer_url(self) -> str:
        return self._peer

    async def _aiohttp_call(self, method: str, url: str, json_body: dict) -> tuple[int, dict]:
        try:
            import aiohttp
        except ImportError as exc:  # pragma: no cover
            raise ImportError("RelaySyncer requires: pip install 'fg-amp[http]'") from exc
        if self._session is None:
            self._session = aiohttp.ClientSession()
        async with self._session.request(
            method, url, json=json_body or None, timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            data = await response.json() if response.content_type == "application/json" else {}
            return response.status, data

    async def aclose(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def _fetch(self, path: str, since: int) -> dict:
        status, data = await self._http_call("GET", f"{self._peer}{path}?since={since}", {})
        if status >= 400:
            raise ConnectionError(f"peer {self._peer} answered HTTP {status} for {path}")
        return data

    async def sync_once(self) -> dict[str, int]:
        """One delta round: cards, delegation revocations, key revocations.

        Returns admit/reject counters. Every record is verified before it is
        admitted; a record that fails verification (hostile peer, corruption)
        is rejected without poisoning the rest of the batch. Cursors advance
        even when some records were rejected — a record the peer serves
        malformed today will be malformed tomorrow, and stalling the cursor on
        it would wedge the sync forever.
        """
        counts = {"cards": 0, "revocations": 0, "key_revocations": 0, "rejected": 0}

        data = await self._fetch(CARDS_PATH, self._cards_cursor)
        for wire in data.get("cards", []):
            try:
                card = AgentCard.model_validate(wire)
                card.verify()
                await self._state.run(self._state.put_card, card)
                counts["cards"] += 1
            except Exception as exc:  # noqa: BLE001 — hostile record: reject, continue
                counts["rejected"] += 1
                logger.warning("rejecting card from peer %s: %s", self._peer, exc)
        self._cards_cursor = int(data.get("cursor", self._cards_cursor))

        data = await self._fetch(REVOCATIONS_PATH, self._rev_cursor)
        for wire in data.get("revocations", []):
            try:
                revocation = Revocation.model_validate(wire)
                revocation.verify()
                await self._state.run(self._state.add_revocation, revocation)
                counts["revocations"] += 1
            except Exception as exc:  # noqa: BLE001 — hostile record: reject, continue
                counts["rejected"] += 1
                logger.warning("rejecting revocation from peer %s: %s", self._peer, exc)
        self._rev_cursor = int(data.get("cursor", self._rev_cursor))

        data = await self._fetch(KEY_REVOCATIONS_PATH, self._key_rev_cursor)
        for wire in data.get("key_revocations", []):
            try:
                revocation = KeyRevocation.model_validate(wire)
                revocation.verify()
                await self._state.run(self._state.add_key_revocation, revocation)
                counts["key_revocations"] += 1
            except Exception as exc:  # noqa: BLE001 — hostile record: reject, continue
                counts["rejected"] += 1
                logger.warning("rejecting key-revocation from peer %s: %s", self._peer, exc)
        self._key_rev_cursor = int(data.get("cursor", self._key_rev_cursor))

        return counts

    async def run(self, interval: float = DEFAULT_SYNC_INTERVAL_SECONDS) -> None:
        """Sync forever, every ``interval`` seconds. Peer downtime is logged
        and retried next round — federation is best-effort convergence."""
        try:
            while True:
                try:
                    await self.sync_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — peer down: retry next round
                    logger.info("sync with %s failed: %s", self._peer, exc)
                await asyncio.sleep(interval)
        finally:
            await self.aclose()
