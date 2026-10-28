import base64
import sqlite3
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, g, jsonify, request

DB_FILE = "totally_not_my_privateKeys.db"
app = Flask(__name__)


# ---------- database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_FILE)
    db.execute("""CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )""")
    db.commit()
    return db


def generate_key(db, exp):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    db.execute("INSERT INTO keys(key, exp) VALUES (?, ?)", (pem, exp))
    db.commit()


def seed_keys():
    """Make sure there is at least one valid key and one expired key."""
    db = init_db()
    now = int(time.time())
    if not db.execute("SELECT 1 FROM keys WHERE exp > ?", (now,)).fetchone():
        generate_key(db, now + 3600)
    if not db.execute("SELECT 1 FROM keys WHERE exp <= ?", (now,)).fetchone():
        generate_key(db, now - 3600)
    db.close()


# ---------- JWKS ----------
def b64url_uint(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@app.get("/.well-known/jwks.json")
def jwks():
    rows = get_db().execute(
        "SELECT kid, key FROM keys WHERE exp > ?", (int(time.time()),)
    ).fetchall()
    keys = []
    for r in rows:
        priv = serialization.load_pem_private_key(r["key"], password=None)
        nums = priv.public_key().public_numbers()
        keys.append({
            "kty": "RSA", "alg": "RS256", "use": "sig",
            "kid": str(r["kid"]),
            "n": b64url_uint(nums.n),
            "e": b64url_uint(nums.e),
        })
    return jsonify(keys=keys)


# ---------- auth ----------
@app.post("/auth")
def auth():
    db = get_db()
    now = int(time.time())
    expired = "expired" in request.args

    if expired:
        row = db.execute(
            "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (now,)
        ).fetchone()
        exp = now - 3600
    else:
        row = db.execute(
            "SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (now,)
        ).fetchone()
        exp = now + 3600

    if not row:
        return jsonify(error="no suitable key"), 500

    token = jwt.encode(
        {"sub": "userABC", "iat": now, "exp": exp},
        row["key"],
        algorithm="RS256",
        headers={"kid": str(row["kid"])},
    )
    return token


if __name__ == "__main__":
    seed_keys()
    app.run(port=8080)