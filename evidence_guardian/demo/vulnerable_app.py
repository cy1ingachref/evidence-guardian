"""Demo vulnerable app for EvidenceGuardian testing.

This app intentionally contains common vulnerabilities for testing.
DO NOT deploy this to production or any public server.
"""
from flask import Flask, request, redirect, jsonify, make_response
import sqlite3
import os

app = Flask(__name__)

# In-memory SQLite for demo
DB_PATH = "/tmp/evidence_guardian_demo.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'alice', 'alice@example.com', 'admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'bob', 'bob@example.com', 'user')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (3, 'charlie', 'charlie@example.com', 'user')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({"status": "ok", "message": "EvidenceGuardian Demo Target"})


@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    """IDOR-vulnerable endpoint: no authorization check on user_id."""
    conn = sqlite3.connect(DB_PATH)
    user = conn.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return jsonify({"id": user[0], "username": user[1], "email": user[2], "role": user[3]})
    return jsonify({"error": "User not found"}), 404


@app.route("/api/fetch")
def fetch_url():
    """SSRF-vulnerable endpoint: fetches user-supplied URL."""
    import urllib.request
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EvidenceGuardian-Demo"})
        # Only fetch to demonstrate - don't actually expose sensitive data
        if "169.254" in url or "127.0.0.1" in url or "localhost" in url:
            return jsonify({"status": "internal_access_simulated", "message": "If this were real, internal metadata would be exposed"}), 200
        return jsonify({"status": "fetch_attempted", "url": url}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/search")
def search():
    """XSS-vulnerable endpoint: reflects search query without encoding."""
    q = request.args.get("q", "")
    response = make_response(jsonify({"query": q, "results": [], "html": f"<div>Results for: {q}</div>"}))
    response.headers["Content-Type"] = "application/json"
    return response


@app.route("/api/login", methods=["GET"])
def login():
    """SQLi-vulnerable endpoint: string concatenation in SQL."""
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    try:
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
    except Exception as e:
        return jsonify({"error": f"SQL error: {str(e)}"}), 500
    finally:
        conn.close()
    if user:
        return jsonify({"status": "logged_in", "user": user[1]})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/login")
def login_redirect():
    """Open redirect-vulnerable endpoint."""
    next_url = request.args.get("next", "/")
    return redirect(next_url)


@app.route("/api/proxy")
def proxy():
    """Another SSRF endpoint for proxy testing."""
    url = request.args.get("target", "")
    if not url:
        return jsonify({"error": "target parameter required"}), 400
    return jsonify({"proxied": True, "url": url}), 200


if __name__ == "__main__":
    init_db()
    print("EvidenceGuardian Demo Server")
    print("WARNING: This app is intentionally vulnerable. Do NOT expose to public networks.")
    print("Starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
