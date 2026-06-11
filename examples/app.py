#!/usr/bin/env python3
"""Example application: a tiny article API protected by authcore.

Demonstrates the full flow — login for a JWT, then call endpoints that
require different permissions depending on the caller's role.

Seeded demo users (DO NOT seed users like this in production):

    username   password      role     can do
    ---------  ------------  -------  ---------------------------------
    alice      alicepass123  admin    read, write, delete (inherits all)
    bob        bobpass12345  editor   read, write
    carol      carolpass123  reader   read

Run:
    export AUTH_SECRET="dev-only-secret-change-me-0123456789"
    python examples/app.py

Try it:
    # 1. login
    TOKEN=$(curl -s -X POST localhost:5000/login \
        -H 'Content-Type: application/json' \
        -d '{"username":"carol","password":"carolpass123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

    # 2. read — allowed for reader
    curl -s localhost:5000/articles -H "Authorization: Bearer $TOKEN"

    # 3. write — 403 for reader
    curl -s -X POST localhost:5000/articles \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
        -d '{"title":"New post"}'
"""

import os
import sys
from datetime import timedelta
from functools import wraps

from flask import Flask, g, jsonify, request

# Allow running directly from the repo without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from authcore import (  # noqa: E402
    AuthError,
    AuthService,
    InMemoryUserStore,
    InvalidCredentialsError,
    PermissionDeniedError,
    RBACPolicy,
    TokenError,
    TokenManager,
)

# --------------------------------------------------------------------------
# 1. Configure the library
# --------------------------------------------------------------------------
SECRET = os.environ.get("AUTH_SECRET", "dev-only-secret-change-me-0123456789")

policy = RBACPolicy()
policy.add_role("reader", grants=["articles:read"])
policy.add_role("editor", inherits=["reader"], grants=["articles:write"])
policy.add_role("admin", inherits=["editor"], grants=["articles:delete"])

auth = AuthService(
    user_store=InMemoryUserStore(),
    token_manager=TokenManager(SECRET, access_ttl=timedelta(minutes=30), issuer="example-app"),
    policy=policy,
)

# Seed demo users (a real app would have a registration flow / database).
auth.register("alice", "alicepass123", roles=("admin",))
auth.register("bob", "bobpass12345", roles=("editor",))
auth.register("carol", "carolpass123", roles=("reader",))

# --------------------------------------------------------------------------
# 2. A tiny Flask integration layer (~25 lines)
# --------------------------------------------------------------------------
app = Flask(__name__)

ARTICLES = {1: {"id": 1, "title": "Hello, queue!"}, 2: {"id": 2, "title": "JWTs in practice"}}
_next_id = 3


def require_permission(permission: str):
    """Decorator: verify the bearer token and enforce an RBAC permission."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="missing bearer token"), 401
            g.identity = auth.authorize(header.removeprefix("Bearer "), permission)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


@app.errorhandler(TokenError)
def _token_error(exc):  # bad/expired token -> 401
    return jsonify(error=str(exc)), 401


@app.errorhandler(PermissionDeniedError)
def _forbidden(exc):  # valid token, insufficient role -> 403
    return jsonify(error=str(exc)), 403


@app.errorhandler(AuthError)
def _auth_error(exc):
    return jsonify(error=str(exc)), 400


# --------------------------------------------------------------------------
# 3. Routes
# --------------------------------------------------------------------------
@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    try:
        token = auth.login(body.get("username", ""), body.get("password", ""))
    except InvalidCredentialsError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(access_token=token, token_type="bearer")


@app.get("/me")
@require_permission("articles:read")
def me():
    return jsonify(username=g.identity.username, roles=list(g.identity.roles))


@app.get("/articles")
@require_permission("articles:read")
def list_articles():
    return jsonify(articles=list(ARTICLES.values()))


@app.post("/articles")
@require_permission("articles:write")
def create_article():
    global _next_id
    body = request.get_json(silent=True) or {}
    article = {"id": _next_id, "title": body.get("title", "untitled"),
               "author": g.identity.username}
    ARTICLES[_next_id] = article
    _next_id += 1
    return jsonify(article), 201


@app.delete("/articles/<int:article_id>")
@require_permission("articles:delete")
def delete_article(article_id: int):
    if ARTICLES.pop(article_id, None) is None:
        return jsonify(error="not found"), 404
    return "", 204


if __name__ == "__main__":
    app.run(port=5000)
