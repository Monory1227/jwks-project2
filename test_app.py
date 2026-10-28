"""Tests for the Project 2 JWKS server."""
import base64
import json
import sqlite3
import time

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

import app as server


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Test client backed by a throwaway SQLite file."""
    monkeypatch.setattr(server, "DB_FILE", str(tmp_path / "test.db"))
    server.seed_keys()
    return server.app.test_client()


def fetch_jwks(client):
    return client.get("/.well-known/jwks.json").get_json()["keys"]


def test_keys_are_persisted_in_database(client):
    db = sqlite3.connect(server.DB_FILE)
    rows = db.execute("SELECT key, exp FROM keys").fetchall()
    db.close()
    assert len(rows) == 2
    assert all(b"BEGIN PRIVATE KEY" in row[0] for row in rows)


def test_seed_keys_does_not_duplicate(client):
    server.seed_keys()
    db = sqlite3.connect(server.DB_FILE)
    count = db.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    db.close()
    assert count == 2


def test_jwks_serves_only_unexpired_keys(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    keys = resp.get_json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "RSA"
    assert keys[0]["alg"] == "RS256"
    assert {"kid", "n", "e"} <= keys[0].keys()


def test_auth_token_verifies_against_jwks(client):
    token = client.post("/auth").get_data(as_text=True)
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next(k for k in fetch_jwks(client) if k["kid"] == kid)
    public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(token, public_key, algorithms=["RS256"])
    assert claims["sub"] == "userABC"


def test_auth_expired_uses_expired_key(client):
    token = client.post("/auth?expired=true").get_data(as_text=True)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] < time.time()
    kid = jwt.get_unverified_header(token)["kid"]
    assert kid not in [k["kid"] for k in fetch_jwks(client)]


def test_auth_accepts_basic_auth_and_json_body(client):
    creds = base64.b64encode(b"userABC:password123").decode()
    resp = client.post(
        "/auth",
        json={"username": "userABC", "password": "password123"},
        headers={"Authorization": f"Basic {creds}"},
    )
    assert resp.status_code == 200


def test_auth_without_keys_returns_500(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DB_FILE", str(tmp_path / "empty.db"))
    server.init_db().close()
    resp = server.app.test_client().post("/auth")
    assert resp.status_code == 500