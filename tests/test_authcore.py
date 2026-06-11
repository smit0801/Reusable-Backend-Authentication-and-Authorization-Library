"""Unit tests for authcore."""

import sys
import time
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from authcore import (  # noqa: E402
    AuthService,
    InMemoryUserStore,
    InvalidCredentialsError,
    PasswordHasher,
    PermissionDeniedError,
    RBACPolicy,
    TokenExpiredError,
    TokenInvalidError,
    TokenManager,
    UserAlreadyExistsError,
)

SECRET = "unit-test-secret-key-0123456789abcdef"


# -- passwords ---------------------------------------------------------------

def test_password_roundtrip():
    hasher = PasswordHasher(iterations=100_000)  # low count to keep tests fast
    encoded = hasher.hash("s3cret!")
    assert hasher.verify("s3cret!", encoded)
    assert not hasher.verify("wrong", encoded)
    assert "s3cret!" not in encoded


def test_password_salts_are_unique():
    hasher = PasswordHasher(iterations=100_000)
    assert hasher.hash("same") != hasher.hash("same")


def test_needs_rehash_on_weaker_params():
    old = PasswordHasher(iterations=100_000).hash("pw")
    assert PasswordHasher(iterations=200_000).needs_rehash(old)


# -- tokens ------------------------------------------------------------------

def test_token_roundtrip_carries_roles():
    tm = TokenManager(SECRET)
    claims = tm.verify(tm.issue("alice", roles=["admin"]))
    assert claims["sub"] == "alice"
    assert claims["roles"] == ["admin"]


def test_token_expiry():
    tm = TokenManager(SECRET, access_ttl=timedelta(seconds=1))
    token = tm.issue("alice")
    time.sleep(1.2)
    with pytest.raises(TokenExpiredError):
        tm.verify(token)


def test_tampered_token_rejected():
    tm = TokenManager(SECRET)
    other = TokenManager("a-completely-different-secret-key-xyz")
    with pytest.raises(TokenInvalidError):
        tm.verify(other.issue("mallory", roles=["admin"]))


def test_reserved_claims_protected():
    tm = TokenManager(SECRET)
    with pytest.raises(ValueError):
        tm.issue("alice", extra_claims={"sub": "mallory"})


def test_short_hmac_secret_rejected():
    with pytest.raises(ValueError):
        TokenManager("short")


# -- rbac --------------------------------------------------------------------

@pytest.fixture()
def policy():
    p = RBACPolicy()
    p.add_role("reader", grants=["articles:read"])
    p.add_role("editor", inherits=["reader"], grants=["articles:write"])
    p.add_role("admin", inherits=["editor"], grants=["*"])
    return p


def test_inheritance(policy):
    assert policy.is_allowed(["editor"], "articles:read")
    assert not policy.is_allowed(["reader"], "articles:write")


def test_wildcards(policy):
    assert policy.is_allowed(["admin"], "anything:at_all")
    p = RBACPolicy()
    p.grant("ops", "deploy:*")
    assert p.is_allowed(["ops"], "deploy:restart")
    assert not p.is_allowed(["ops"], "billing:read")


def test_unknown_role_confers_nothing(policy):
    assert policy.permissions_for(["ghost"]) == frozenset()


def test_require_raises(policy):
    with pytest.raises(PermissionDeniedError):
        policy.require(["reader"], "articles:delete")


def test_inheritance_cycle_detected():
    p = RBACPolicy()
    p.add_role("a")
    p.add_role("b", inherits=["a"])
    with pytest.raises(ValueError):
        p.add_role("a", inherits=["b"])


# -- service facade ------------------------------------------------------------

@pytest.fixture()
def service(policy):
    svc = AuthService(
        InMemoryUserStore(),
        TokenManager(SECRET),
        policy,
        hasher=PasswordHasher(iterations=100_000),
    )
    svc.register("alice", "alicepass123", roles=("admin",))
    svc.register("carol", "carolpass123", roles=("reader",))
    return svc


def test_login_and_authorize_flow(service):
    token = service.login("alice", "alicepass123")
    identity = service.authorize(token, "articles:delete")
    assert identity.username == "alice"


def test_reader_denied_delete(service):
    token = service.login("carol", "carolpass123")
    with pytest.raises(PermissionDeniedError):
        service.authorize(token, "articles:delete")


def test_wrong_password_and_unknown_user_same_error(service):
    with pytest.raises(InvalidCredentialsError) as e1:
        service.login("alice", "nope")
    with pytest.raises(InvalidCredentialsError) as e2:
        service.login("nobody", "nope")
    assert str(e1.value) == str(e2.value)  # no username enumeration


def test_duplicate_registration_rejected(service):
    with pytest.raises(UserAlreadyExistsError):
        service.register("alice", "again", roles=())
