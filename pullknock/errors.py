"""Project-specific exceptions."""


class PullKnockError(Exception):
    """Base class for expected PullKnock failures."""


class ConfigError(PullKnockError):
    """Configuration is missing or invalid."""


class ProtocolError(PullKnockError):
    """Envelope or payload data does not match the protocol."""


class SigningError(PullKnockError):
    """Signing failed."""


class SignatureVerificationError(SigningError):
    """Signature verification failed."""


class PublishError(PullKnockError):
    """Publishing an envelope failed."""


class FetchError(PullKnockError):
    """Fetching an envelope failed."""


class PermissionDenied(PullKnockError):
    """A signed command is not permitted by local policy."""


class DuplicateCommand(PullKnockError):
    """The command_id has already been processed."""


class ExpiredCommand(PullKnockError):
    """The command is outside its valid time window."""


class NotYetValidCommand(PullKnockError):
    """The command is not valid yet."""


class FirewallError(PullKnockError):
    """Firewall backend command failed."""
