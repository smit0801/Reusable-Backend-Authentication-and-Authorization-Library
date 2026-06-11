"""Role-based access control (RBAC) with role inheritance and wildcards.

Permissions are plain strings, conventionally ``"resource:action"``
(e.g. ``"articles:read"``). A role granted ``"articles:*"`` holds every
permission in the ``articles`` namespace; ``"*"`` grants everything.

Roles may inherit from other roles::

    policy = RBACPolicy()
    policy.add_role("reader",  grants=["articles:read"])
    policy.add_role("editor",  inherits=["reader"], grants=["articles:write"])
    policy.add_role("admin",   inherits=["editor"], grants=["*"])
"""

from __future__ import annotations

from typing import Iterable, Sequence

from .exceptions import PermissionDeniedError


class RBACPolicy:
    """An in-memory mapping of roles to permissions."""

    def __init__(self) -> None:
        self._grants: dict[str, set[str]] = {}
        self._parents: dict[str, set[str]] = {}

    def add_role(
        self,
        role: str,
        *,
        grants: Iterable[str] = (),
        inherits: Iterable[str] = (),
    ) -> None:
        """Define (or extend) ``role`` with permissions and parent roles."""
        for parent in inherits:
            if parent not in self._grants:
                raise ValueError(f"unknown parent role: {parent!r}")
        self._grants.setdefault(role, set()).update(grants)
        self._parents.setdefault(role, set()).update(inherits)
        self._check_no_cycle(role)

    def grant(self, role: str, *permissions: str) -> None:
        """Add permissions to an existing (or new) role."""
        self._grants.setdefault(role, set()).update(permissions)
        self._parents.setdefault(role, set())

    def permissions_for(self, roles: Sequence[str]) -> frozenset[str]:
        """Resolve the full permission set for ``roles``, inheritance included.

        Unknown roles are ignored rather than raised: a token minted before
        a role was retired should simply confer nothing for that role.
        """
        resolved: set[str] = set()
        stack = [r for r in roles if r in self._grants]
        seen: set[str] = set()
        while stack:
            role = stack.pop()
            if role in seen:
                continue
            seen.add(role)
            resolved.update(self._grants.get(role, ()))
            stack.extend(self._parents.get(role, ()))
        return frozenset(resolved)

    def is_allowed(self, roles: Sequence[str], permission: str) -> bool:
        """True if any of ``roles`` (or their ancestors) holds ``permission``."""
        held = self.permissions_for(roles)
        if permission in held or "*" in held:
            return True
        namespace = permission.split(":", 1)[0]
        return f"{namespace}:*" in held

    def require(self, roles: Sequence[str], permission: str) -> None:
        """Raise :class:`PermissionDeniedError` unless allowed."""
        if not self.is_allowed(roles, permission):
            raise PermissionDeniedError(
                f"permission {permission!r} required"
            )

    def _check_no_cycle(self, start: str) -> None:
        seen: set[str] = set()
        stack = [start]
        while stack:
            role = stack.pop()
            if role in seen:
                if role == start:
                    raise ValueError(f"role inheritance cycle involving {start!r}")
                continue
            seen.add(role)
            stack.extend(self._parents.get(role, ()))
