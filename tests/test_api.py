"""Unit tests for the secure API.

Run from the project root:  pytest -q
"""
import os
import tempfile

# Important: the environment must be configured BEFORE `import app`,
# because app.py reads these values at import time.
os.environ["APP_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["JWT_SECRET"] = "test-secret"

import app as appmod  # noqa: E402

appmod.init_db()
client = appmod.app.test_client()


def _token():
    r = client.post("/auth/login", json={"username": "alice", "password": "AlicePassw0rd!"})
    assert r.status_code == 200
    return r.get_json()["token"]


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_data_requires_token():
    assert client.get("/api/data").status_code == 401


def test_data_rejects_bad_token():
    r = client.get("/api/data", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_login_ok():
    r = client.post("/auth/login", json={"username": "alice", "password": "AlicePassw0rd!"})
    assert r.status_code == 200
    assert "token" in r.get_json()


def test_login_wrong_password():
    r = client.post("/auth/login", json={"username": "alice", "password": "nope"})
    assert r.status_code == 401


def test_sqli_payload_rejected():
    """Parameterised queries: the injection string must be treated as a plain username."""
    r = client.post("/auth/login", json={"username": "alice' OR '1'='1", "password": "x"})
    assert r.status_code == 401


def test_data_with_token():
    r = client.get("/api/data", headers={"Authorization": f"Bearer {_token()}"})
    assert r.status_code == 200
    assert len(r.get_json()["data"]) >= 2


def test_post_requires_token():
    r = client.post("/api/posts", json={"title": "a", "body": "b"})
    assert r.status_code == 401


def test_xss_output_is_escaped():
    r = client.post(
        "/api/posts",
        json={"title": "<script>alert(1)</script>", "body": "xss"},
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert r.status_code == 201
    title = r.get_json()["title"]
    assert "<script>" not in title
    assert "&lt;script&gt;" in title


def test_post_author_comes_from_token():
    """The author must be derived from the JWT, never from the request body."""
    r = client.post(
        "/api/posts",
        json={"title": "hello", "body": "world", "user_id": 2},
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert r.status_code == 201
    assert r.get_json()["author"] == "alice"
