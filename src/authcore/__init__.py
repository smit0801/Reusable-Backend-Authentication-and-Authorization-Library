"""authcore — a reusable authentication (JWT) and authorization (RBAC) library.

Public API::

    from authcore import (
        AuthService, InMemoryUserStore, UserStore, User, Identity,
        TokenManager, RBACPolicy, PasswordHasher,
        AuthError, InvalidCredentialsError, UserAlreadyExistsError,
        TokenError, TokenExpiredError, TokenInvalidError,
        PermissionDeniedError,
    )
"""

from .exceptions import (
    AuthError,
    InvalidCredentialsError,
    PermissionDeniedError,
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    UserAlreadyExistsError,
)
from .passwords import PasswordHasher
from .rbac import RBACPolicy
from .service import AuthService, Identity, InMemoryUserStore, User, UserStore
from .tokens import TokenManager

__version__ = "0.1.0"

__all__ = [
    "AuthService",
    "AuthError",
    "Identity",
    "InMemoryUserStore",
    "InvalidCredentialsError",
    "PasswordHasher",
    "PermissionDeniedError",
    "RBACPolicy",
    "TokenError",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenManager",
    "User",
    "UserAlreadyExistsError",
    "UserStore",
]
