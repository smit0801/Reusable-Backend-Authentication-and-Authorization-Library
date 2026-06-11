"""Password hashing with PBKDF2-HMAC-SHA256 (standard library only).

Encoded format (Django-style, self-describing so parameters can evolve):

    pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>

Security notes:
- Per-password random 16-byte salt (``os.urandom``).
- 600,000 iterations by default (OWASP 2023+ recommendation for
  PBKDF2-SHA256).
- Constant-time comparison via :func:`hmac.compare_digest`.
- ``needs_rehash`` lets applications transparently upgrade stored hashes
  when the iteration count is raised.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

_SCHEME = "pbkdf2_sha256"


class PasswordHasher:
    """Hashes and verifies passwords.

    Parameters
    ----------
    iterations:
        PBKDF2 iteration count used for *new* hashes. Verification reads
        the count from the stored hash, so raising this value never breaks
        existing credentials.
    """

    def __init__(self, iterations: int = 600_000) -> None:
        if iterations < 100_000:
            raise ValueError("iterations must be >= 100,000")
        self.iterations = iterations

    def hash(self, password: str) -> str:
        """Return an encoded hash for ``password``."""
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, self.iterations
        )
        return "$".join(
            (
                _SCHEME,
                str(self.iterations),
                base64.b64encode(salt).decode("ascii"),
                base64.b64encode(digest).decode("ascii"),
            )
        )

    def verify(self, password: str, encoded: str) -> bool:
        """Constant-time check of ``password`` against an encoded hash."""
        try:
            scheme, iter_s, salt_b64, hash_b64 = encoded.split("$")
            if scheme != _SCHEME:
                return False
            iterations = int(iter_s)
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
        except (ValueError, TypeError):
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(candidate, expected)

    def needs_rehash(self, encoded: str) -> bool:
        """True if the stored hash uses weaker parameters than current."""
        try:
            scheme, iter_s, *_ = encoded.split("$")
            return scheme != _SCHEME or int(iter_s) < self.iterations
        except (ValueError, TypeError):
            return True
