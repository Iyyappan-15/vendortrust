"""
app/services/exceptions.py — Domain & Security Exceptions for VendorTrust
"""

class VendorTrustError(Exception):
    """Base domain error for VendorTrust."""
    pass


class SecurityViolationError(VendorTrustError):
    """Raised when an authorization invariant or boundary is violated (e.g. self-approval)."""
    pass


class InvalidStateTransitionError(VendorTrustError):
    """Raised when an entity attempts an illegal state machine transition."""
    pass


class InvalidChallengeError(VendorTrustError):
    """Raised when an invalid verification token is presented."""
    pass


class ExpiredChallengeError(VendorTrustError):
    """Raised when a verification challenge has expired."""
    pass


class MaxAttemptsExceededError(VendorTrustError):
    """Raised when maximum verification attempts are reached."""
    pass


class VendorFrozenError(VendorTrustError):
    """Raised when an operation is attempted on a frozen/compromised vendor."""
    pass


class StaleVersionError(VendorTrustError):
    """Raised when an approval references a superseded or inactive vendor version."""
    pass


class DuplicatePayoutError(VendorTrustError):
    """Raised when a duplicate payout instruction or concurrent reservation is attempted."""
    pass
