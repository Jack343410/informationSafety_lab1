import os
import html
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

DB_PATH = os.environ.get("APP_DB", os.path.join(os.path.dirname(__file__), "app.db"))
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-change-me-before-grading")
JWT_ALG = "HS256"
TOKEN_TTL_MIN = int(os.environ.get("TOKEN_TTL_MIN", "30"))

app = Flask(__name__)


# ---------- database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'user'
            );
            CREATE TABLE IF NOT EXISTS posts (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                title   TEXT NOT NULL,
                body    TEXT NOT NULL
            );
            """
        )
        exists = db.execute("SELECT 1 FROM users WHERE username = ?", ("alice",)).fetchone()
        if not exists:
            for name, pw in (("alice", "AlicePassw0rd!"), ("bob", "BobPassw0rd!")):
                h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)", (name, h)
                )
        db.commit()


# ---------- security helpers ----------
def clean(value):
    """XSS defence in depth: escape every string field before returning it."""
    return html.escape(str(value), quote=True)


def make_token(row):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(row["id"]),
        "username": row["username"],
        "role": row["role"],
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_TTL_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def token_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify(error="missing or malformed Authorization header"), 401
        token = auth[7:].strip()
        try:
            claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except jwt.ExpiredSignatureError:
            return jsonify(error="token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="invalid token"), 401
        g.user = claims
        return view(*args, **kwargs)

    return wrapper


# ---------- endpoint 1: login ----------
@app.post("/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return jsonify(error="username and password are required"), 400

    # Parameterised query: "alice' OR '1'='1" is treated as a plain string.
    row = get_db().execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
    ).fetchone()

    if row is None or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return jsonify(error="invalid credentials"), 401

    return jsonify(token=make_token(row), token_type="Bearer", expires_in=TOKEN_TTL_MIN * 60)


# ---------- endpoint 2: protected read ----------
@app.get("/api/data")
@token_required
def api_data():
    rows = get_db().execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    return jsonify(
        data=[
            {"id": r["id"], "username": clean(r["username"]), "role": clean(r["role"])}
            for r in rows
        ]
    )


# ---------- endpoint 3: my own (protected write) ----------
@app.post("/api/posts")
@token_required
def create_post():
    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip()
    text = (body.get("body") or "").strip()
    if not title or not text:
        return jsonify(error="title and body are required"), 400
    if len(title) > 120 or len(text) > 2000:
        return jsonify(error="title max 120 chars, body max 2000 chars"), 400

    # The author always comes from the token, never from the request body.
    author_id = int(g.user["sub"])
    db = get_db()
    cur = db.execute(
        "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)", (author_id, title, text)
    )
    db.commit()
    return (
        jsonify(id=cur.lastrowid, title=clean(title), body=clean(text), author=g.user["username"]),
        201,
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
