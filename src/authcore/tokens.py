"""JWT issuance and verification, built on PyJWT.

The library does not implement JOSE primitives itself ("don't roll your
own crypto"); it wraps PyJWT with safe defaults:

- Algorithm is pinned at construction time and enforced on verification,
  preventing algorithm-confusion attacks (e.g. ``alg: none``).
- Every token carries ``iat``, ``exp``, and a unique ``jti``.
- ``exp`` (and ``iss``/``aud`` when configured) are strictly verified.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

import jwt

from .exceptions import TokenExpiredError, TokenInvalidError

#: Claims applications may not override via ``extra_claims``.
_RESERVED = {"sub", "iat", "exp", "jti", "iss", "aud", "roles"}


class TokenManager:
    """Issues and verifies signed JWT access tokens.

    Parameters
    ----------
    secret_key:
        HMAC signing key. Must be long and random (>= 32 bytes); load it
        from configuration or a secret manager, never hard-code it.
    algorithm:
        Signing algorithm, default ``HS256``. Asymmetric algorithms
        (``RS256``/``ES256``) work too if you pass the appropriate keys.
    access_ttl:
        Lifetime of issued tokens (default 15 minutes — short lifetimes
        bound the damage of a leaked token).
    issuer / audience:
        Optional ``iss``/``aud`` claims, enforced on verification when set.
    leeway:
        Clock-skew tolerance in seconds when validating ``exp``.
    """

    def __init__(
        self,
        secret_key: str,
        *,
        algorithm: str = "HS256",
        access_ttl: timedelta = timedelta(minutes=15),
        issuer: str | None = None,
        audience: str | None = None,
        leeway: int = 0,
    ) -> None:
        if algorithm.startswith("HS") and len(secret_key) < 32:
            raise ValueError("secret_key must be at least 32 characters for HMAC")
        self._secret = secret_key
        self._algorithm = algorithm
        self._ttl = access_ttl
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway

    def issue(
        self,
        subject: str,
        *,
        roles: Sequence[str] = (),
        extra_claims: Mapping[str, Any] | None = None,
    ) -> str:
        """Create a signed token for ``subject`` carrying its roles."""
        now = datetime.now(timezone.utc)
        claims: dict[str, Any] = {
            "sub": subject,
            "roles": list(roles),
            "iat": now,
            "exp": now + self._ttl,
            "jti": uuid.uuid4().hex,
        }
        if self._issuer:
            claims["iss"] = self._issuer
        if self._audience:
            claims["aud"] = self._audience
        if extra_claims:
            clash = _RESERVED & set(extra_claims)
            if clash:
                raise ValueError(f"extra_claims may not override: {sorted(clash)}")
            claims.update(extra_claims)
        return jwt.encode(claims, self._secret, algorithm=self._algorithm)

    def verify(self, token: str) -> dict[str, Any]:
        """Validate signature and registered claims; return the payload.

        Raises
        ------
        TokenExpiredError
            If the token's ``exp`` is in the past.
        TokenInvalidError
            For any other problem (bad signature, wrong issuer, garbage).
        """
        try:
            return jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],  # pinned — never trust the header
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway,
                options={"require": ["sub", "iat", "exp", "jti"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("token has expired") from exc
        except jwt.InvalidTokenError as exc:
            # Generic message by design: detailed decode errors can leak
            # implementation details to callers. The cause is chained for
            # server-side logging.
            raise TokenInvalidError("invalid token") from exc
