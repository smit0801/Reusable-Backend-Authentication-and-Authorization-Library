# authcore — Reusable Authentication & Authorization Library for Python

A small, dependency-light library implementing two recognized patterns:

- **Authentication: JWT bearer tokens** (stateless, signed access tokens
  via [PyJWT](https://pyjwt.readthedocs.io/)) with PBKDF2-SHA256 password
  hashing from the standard library.
- **Authorization: Role-Based Access Control (RBAC)** with role
  inheritance and namespace wildcards (`articles:*`).

It is framework-agnostic — the example app integrates it with Flask in
~25 lines, and the same core works with FastAPI, Django, CLIs, or workers.

## Why JWT + RBAC?

JWTs make authentication **stateless**: any service holding the signing
key can verify a request without a session-store lookup, which suits
horizontally-scaled APIs and microservices. RBAC is the most widely
deployed authorization model — simple to reason about, auditable, and
sufficient for the vast majority of applications (ABAC/policy engines are
the step up when you need attribute- or relationship-based rules).

## Repository layout

```
.
├── README.md
├── pyproject.toml            # installable package definition
├── requirements.txt
├── src/authcore/
│   ├── __init__.py           # public API
│   ├── passwords.py          # PasswordHasher (PBKDF2-SHA256, stdlib)
│   ├── tokens.py             # TokenManager (JWT issue/verify)
│   ├── rbac.py               # RBACPolicy (roles, inheritance, wildcards)
│   ├── service.py            # AuthService facade + UserStore interface
│   └── exceptions.py         # typed error hierarchy
├── examples/
│   └── app.py                # Flask demo: login + protected article API
└── tests/
    └── test_authcore.py      # 17 unit tests (pytest)
```

## Quick start

```bash
git clone <this-repo> && cd authcore
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # PyJWT, Flask (example), pytest
python -m pytest tests/ -q             # 17 passed
```

### Run the example application

```bash
export AUTH_SECRET="dev-only-secret-change-me-0123456789"
python examples/app.py                 # serves http://localhost:5000
```

Seeded demo users: `alice/alicepass123` (admin), `bob/bobpass12345`
(editor), `carol/carolpass123` (reader).

In another terminal:

```bash
# 1. Authenticate -> receive a JWT
TOKEN=$(curl -s -X POST localhost:5000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"carol","password":"carolpass123"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 2. Authorized request (reader may read) -> 200
curl -i localhost:5000/articles -H "Authorization: Bearer $TOKEN"

# 3. Forbidden request (reader may not write) -> 403
curl -i -X POST localhost:5000/articles \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Nope"}'
```

Endpoints: `POST /login`, `GET /me`, `GET /articles` (needs
`articles:read`), `POST /articles` (`articles:write`),
`DELETE /articles/<id>` (`articles:delete`).

## Library API

### Five-minute integration

```python
from datetime import timedelta
from authcore import AuthService, InMemoryUserStore, RBACPolicy, TokenManager

policy = RBACPolicy()
policy.add_role("reader", grants=["articles:read"])
policy.add_role("editor", inherits=["reader"], grants=["articles:write"])
policy.add_role("admin",  inherits=["editor"], grants=["*"])

auth = AuthService(
    user_store=InMemoryUserStore(),                    # swap for your DB
    token_manager=TokenManager(SECRET, access_ttl=timedelta(minutes=15)),
    policy=policy,
)

auth.register("carol", "carolpass123", roles=("reader",))
token = auth.login("carol", "carolpass123")            # -> signed JWT

identity = auth.verify(token)                          # 401 path
identity = auth.authorize(token, "articles:read")      # 401/403 path
```

### `PasswordHasher(iterations=600_000)`
| method | description |
|---|---|
| `hash(password) -> str` | PBKDF2-SHA256 with fresh 16-byte salt; self-describing encoded format |
| `verify(password, encoded) -> bool` | constant-time comparison |
| `needs_rehash(encoded) -> bool` | True if stored hash uses weaker parameters (login transparently upgrades) |

### `TokenManager(secret_key, *, algorithm="HS256", access_ttl, issuer=None, audience=None, leeway=0)`
| method | description |
|---|---|
| `issue(subject, *, roles=(), extra_claims=None) -> str` | signed JWT with `sub`, `roles`, `iat`, `exp`, `jti` (+ `iss`/`aud` if configured); reserved claims cannot be overridden |
| `verify(token) -> dict` | enforces signature with a **pinned algorithm**, expiry, required claims; raises `TokenExpiredError` / `TokenInvalidError` |

### `RBACPolicy`
| method | description |
|---|---|
| `add_role(role, *, grants=(), inherits=())` | define a role; inheritance cycles are rejected |
| `grant(role, *permissions)` | add permissions to a role |
| `permissions_for(roles) -> frozenset` | resolved permissions incl. inherited |
| `is_allowed(roles, permission) -> bool` | supports `"ns:*"` and global `"*"` wildcards |
| `require(roles, permission)` | raises `PermissionDeniedError` if not allowed |

### `AuthService(user_store, token_manager, policy, hasher=None)`
| method | description |
|---|---|
| `register(username, password, roles=())` | hash + store a new user |
| `login(username, password) -> token` | verify credentials, return JWT |
| `verify(token) -> Identity` | authenticate a request |
| `authorize(token, permission) -> Identity` | authenticate **and** enforce RBAC |

### Extensibility

- **Storage** — implement the two-method `UserStore` ABC
  (`get_user`, `save_user`) to back the library with PostgreSQL, Redis,
  LDAP, etc. `InMemoryUserStore` is provided for demos/tests.
- **Crypto** — every component is injected: swap `PasswordHasher` for an
  argon2 implementation, or configure `TokenManager` with `RS256` keys
  for asymmetric multi-service verification, without touching the rest.
- **Frameworks** — the core never imports a web framework; see
  `examples/app.py` for the small adapter (decorator + error handlers)
  pattern.

### Exception hierarchy

```
AuthError
├── InvalidCredentialsError      # login failed            -> 401
├── UserAlreadyExistsError       # registration conflict   -> 409
├── TokenError                   #                          -> 401
│   ├── TokenExpiredError
│   └── TokenInvalidError
└── PermissionDeniedError        # valid user, no rights   -> 403
```

## Security considerations

Practices the library implements:

- **No hand-rolled crypto.** JOSE handling delegates to PyJWT; password
  hashing uses `hashlib.pbkdf2_hmac`.
- **Algorithm pinning.** Verification only accepts the algorithm the
  `TokenManager` was constructed with, blocking `alg: none` /
  algorithm-confusion attacks.
- **Strong password storage.** Per-password random salt, 600k PBKDF2
  iterations (OWASP guidance), constant-time verification, transparent
  rehash-on-login when parameters are strengthened.
- **No username enumeration.** Unknown user and wrong password raise the
  identical error.
- **Short token lifetimes** (15 min default) and a unique `jti` per token.
- **Minimal error leakage.** Token failures return a generic message;
  details are exception-chained for server-side logs only.
- **Secret hygiene.** HMAC secrets shorter than 32 chars are rejected at
  construction; the example app reads its secret from the environment.

Things a production deployment must add (out of scope for this prototype):

- **TLS everywhere** — bearer tokens are credentials; never send them in
  plaintext.
- **Refresh tokens + revocation.** Stateless JWTs cannot be revoked
  before expiry; pair short-lived access tokens with stored, revocable
  refresh tokens (the `jti` claim is included to support deny-lists).
- **Rate limiting / lockout** on the login endpoint to slow credential
  stuffing.
- **A real user store** with unique constraints and migrations
  (`InMemoryUserStore` is for demos only).
- Audit logging, MFA, and secret rotation per your threat model.

## Running the tests

```bash
python -m pytest tests/ -v
```

Covers: password round-trip/salting/rehash, token round-trip, expiry,
tamper rejection, reserved-claim protection, RBAC inheritance, wildcards,
cycle detection, unknown roles, the full login→authorize flow, and
username-enumeration resistance.
