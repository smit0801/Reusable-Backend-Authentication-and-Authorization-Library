"""High-level facade tying passwords, tokens, and RBAC together.

Extensibility points:

- :class:`UserStore` is an abstract interface — back it with any database
  by implementing two methods. :class:`InMemoryUserStore` ships for demos
  and tests.
- :class:`AuthService` accepts any :class:`~authcore.passwords.PasswordHasher`,
  :class:`~authcore.tokens.TokenManager`, and
  :class:`~authcore.rbac.RBACPolicy`, so each layer can be swapped or
  configured independently.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .exceptions import InvalidCredentialsError, UserAlreadyExistsError
from .passwords import PasswordHasher
from .rbac import RBACPolicy
from .tokens import TokenManager


@dataclass
class User:
    """A stored principal. ``password_hash`` is never the raw password."""

    username: str
    password_hash: str
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class Identity:
    """The verified principal extracted from a valid token."""

    username: str
    roles: tuple[str, ...]
    claims: dict[str, Any] = field(default_factory=dict)


class UserStore(ABC):
    """Persistence interface. Implement this to back authcore with any DB."""

    @abstractmethod
    def get_user(self, username: str) -> User | None:
        """Return the user, or ``None`` if it does not exist."""

    @abstractmethod
    def save_user(self, user: User) -> None:
        """Insert or update a user record."""


class InMemoryUserStore(UserStore):
    """Dict-backed store for examples and tests (not for production)."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def get_user(self, username: str) -> User | None:
        return self._users.get(username)

    def save_user(self, user: User) -> None:
        self._users[user.username] = user


class AuthService:
    """One object an application talks to for register/login/authorize."""

    def __init__(
        self,
        user_store: UserStore,
        token_manager: TokenManager,
        policy: RBACPolicy,
        hasher: PasswordHasher | None = None,
    ) -> None:
        self.users = user_store
        self.tokens = token_manager
        self.policy = policy
        self.hasher = hasher or PasswordHasher()

    # -- authentication ------------------------------------------------

    def register(self, username: str, password: str, roles: tuple[str, ...] = ()) -> User:
        """Create a user with a hashed password."""
        if self.users.get_user(username) is not None:
            raise UserAlreadyExistsError(f"username {username!r} is taken")
        user = User(username=username, password_hash=self.hasher.hash(password), roles=roles)
        self.users.save_user(user)
        return user

    def login(self, username: str, password: str) -> str:
        """Verify credentials and return a signed access token.

        Raises the same :class:`InvalidCredentialsError` for unknown users
        and wrong passwords, to prevent username enumeration.
        """
        user = self.users.get_user(username)
        if user is None or not self.hasher.verify(password, user.password_hash):
            raise InvalidCredentialsError("invalid username or password")
        if self.hasher.needs_rehash(user.password_hash):
            user.password_hash = self.hasher.hash(password)
            self.users.save_user(user)
        return self.tokens.issue(user.username, roles=user.roles)

    # -- authorization ---------------------------------------------------

    def verify(self, token: str) -> Identity:
        """Validate a token and return the authenticated identity (401 path)."""
        claims = self.tokens.verify(token)
        return Identity(
            username=claims["sub"],
            roles=tuple(claims.get("roles", ())),
            claims=claims,
        )

    def authorize(self, token: str, permission: str) -> Identity:
        """Validate a token AND require ``permission`` (401/403 path)."""
        identity = self.verify(token)
        self.policy.require(identity.roles, permission)
        return identity
