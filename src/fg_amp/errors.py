"""AMP error hierarchy.

``AddressError``, ``SignatureError``, and ``DelegationError`` are raised by the
extracted identity layer (``fg-agent-id``) and are re-exported here as
aliases; they subclass ``AgentIdError`` rather than ``AmpError``. All other
errors remain rooted at ``AmpError``.
"""

from fg_agent_id.errors import (  # noqa: F401
    AddressError,
    DelegationError,
    SignatureError,
)


class AmpError(Exception):
    """Base class for all AMP errors."""


class DecryptionError(AmpError):
    """Ciphertext could not be authenticated/decrypted."""


class PolicyRejection(AmpError):
    """Contact policy rejected an initiation."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SessionError(AmpError):
    """Invalid operation on a session (base for more specific session errors)."""


class SessionStateError(SessionError):
    """Operation not valid for the session's current state (closed/expired)."""


class SessionNotFoundError(SessionError):
    """No session with the given id exists on this node."""


class ResumeError(SessionError):
    """A session resume was refused by the peer or failed to validate."""


class ConfigurationError(SessionError):
    """The node is missing configuration required for the operation."""


class BodyError(AmpError):
    """Base for typed-body (payload schema / lifecycle) errors."""


class BodyValidationError(BodyError):
    """A typed body failed validation against its registered schema."""


class UnknownBodyTypeError(BodyError):
    """A body names a typed content type this registry does not know."""


class TaskLifecycleError(BodyError):
    """An amp.task/1 body is an illegal transition for its task's state."""


class PaymentLifecycleError(BodyError):
    """An amp.payment/1 body is an illegal transition for its payment's state."""


class SpendRejectedError(BodyError):
    """A payment authorization exceeds the delegation chain's spend authority."""


class WitnessError(AmpError):
    """A witness copy failed verification, decryption, or cross-checking."""


class ProtocolVersionError(AmpError):
    """Envelope uses an incompatible protocol major version."""


class SequenceError(AmpError):
    """Out-of-order, replayed, or gapped message sequence."""


class TransportError(AmpError):
    """Envelope could not be delivered."""
