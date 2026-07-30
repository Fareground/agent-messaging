"""Persistent session records and stores.

A ``SessionRecord`` is everything needed to resume a persistent session —
except key material, which is deliberately never persisted. Resume
re-authenticates with identity keys and derives a fresh session key, so a
stolen record alone yields nothing.
"""

from __future__ import annotations

import base64
import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from ..identity.card import AgentCard
from .session import Session
from .states import SessionMode
from .witness import WitnessSpec


class SessionRecord(BaseModel):
    session_id: str
    peer_card: AgentCard
    payload_types: tuple[str, ...]
    expires_at: datetime
    initiator: bool
    send_seq: int
    recv_seq: int
    transcript_head: str  # base64
    transcript_length: int
    peer_owner: str | None = None
    peer_scopes: frozenset[str] = frozenset()
    # Witnessed posture survives a resume: the agreement was bound into the
    # original signed handshake, and dropping it across resume would let a
    # party silently exit the audit trail via a close/resume cycle.
    witness: WitnessSpec | None = None

    model_config = {"frozen": True}

    @classmethod
    def from_session(cls, session: Session) -> SessionRecord:
        if session.mode is not SessionMode.PERSISTENT:
            raise ValueError("only persistent sessions can be recorded")
        return cls(
            session_id=session.session_id,
            peer_card=session.peer_card,
            payload_types=session.payload_types,
            expires_at=session.expires_at,
            initiator=session.initiator,
            send_seq=session._send_seq,
            recv_seq=session._recv_seq,
            transcript_head=base64.b64encode(session.transcript.head).decode(),
            transcript_length=session.transcript.length,
            peer_owner=session.peer_owner,
            peer_scopes=session.peer_scopes,
            witness=session.witness,
        )

    @property
    def transcript_head_bytes(self) -> bytes:
        return base64.b64decode(self.transcript_head)


class SessionStore(ABC):
    """Where a node keeps resumable session records."""

    @abstractmethod
    def save(self, record: SessionRecord) -> None: ...

    @abstractmethod
    def load(self, session_id: str) -> SessionRecord | None: ...

    @abstractmethod
    def delete(self, session_id: str) -> None: ...

    @abstractmethod
    def list_ids(self) -> list[str]: ...


class InMemorySessionStore(SessionStore):
    def __init__(self):
        self._records: dict[str, SessionRecord] = {}

    def save(self, record: SessionRecord) -> None:
        self._records[record.session_id] = record

    def load(self, session_id: str) -> SessionRecord | None:
        return self._records.get(session_id)

    def delete(self, session_id: str) -> None:
        self._records.pop(session_id, None)

    def list_ids(self) -> list[str]:
        return list(self._records)


class FileSessionStore(SessionStore):
    """One JSON file per record under a directory. No secrets inside."""

    def __init__(self, directory: str | Path):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id: str) -> Path:
        # Hash the id so distinct ids can never collide to the same file (a
        # sanitize-and-drop scheme could), while keeping filenames filesystem-safe.
        import hashlib

        digest = hashlib.sha256(session_id.encode()).hexdigest()[:32]
        return self._dir / f"{digest}.json"

    def save(self, record: SessionRecord) -> None:
        self._path(record.session_id).write_text(
            json.dumps(record.model_dump(mode="json"), indent=2)
        )

    def load(self, session_id: str) -> SessionRecord | None:
        path = self._path(session_id)
        if not path.exists():
            return None
        return SessionRecord.model_validate(json.loads(path.read_text()))

    def delete(self, session_id: str) -> None:
        self._path(session_id).unlink(missing_ok=True)

    def list_ids(self) -> list[str]:
        # Filenames are hashes, so read the stored session_id from each record.
        ids = []
        for path in self._dir.glob("*.json"):
            try:
                ids.append(json.loads(path.read_text())["session_id"])
            except (OSError, KeyError, json.JSONDecodeError):
                continue
        return ids
