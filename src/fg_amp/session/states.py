"""Session lifecycle states and modes."""

from enum import StrEnum


class SessionState(StrEnum):
    PENDING = "pending"        # initiate sent/received, awaiting decision
    ESTABLISHED = "established"
    REJECTED = "rejected"
    CLOSED = "closed"
    EXPIRED = "expired"


class SessionMode(StrEnum):
    EPHEMERAL = "ephemeral"    # TTL-bound, in-memory keys, transcript discarded on close
    PERSISTENT = "persistent"  # resumable, durable transcript
