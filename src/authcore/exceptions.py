"""Typed exceptions raised by authcore.

Catching :class:`AuthError` handles every failure the library can raise;
the subclasses let applications map failures to precise HTTP statuses
(401 for authentication problems, 403 for authorization problems).
"""


class AuthError(Exception):
    """Base class for all authcore errors."""


class InvalidCredentialsError(AuthError):
    """Username/password verification failed.

    Deliberately raised for *both* unknown-user and wrong-password cases
    so callers cannot enumerate valid usernames from error messages.
    """


class UserAlreadyExistsError(AuthError):
    """Attempted to register a username that is already taken."""


class TokenError(AuthError):
    """Base class for token verification failures (HTTP 401)."""


class TokenExpiredError(TokenError):
    """The token's ``exp`` claim is in the past."""


class TokenInvalidError(TokenError):
    """The token is malformed, has a bad signature, or wrong claims."""


class PermissionDeniedError(AuthError):
    """The authenticated principal lacks a required permission (HTTP 403)."""
