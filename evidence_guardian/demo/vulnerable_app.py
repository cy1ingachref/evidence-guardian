"""Vulnerable Flask app for demo purposes.

This app intentionally contains common vulnerabilities for testing
EvidenceGuardian. DO NOT deploy this to production or any public server.
"""
from flask import Flask, request, redirect, jsonify, make_response
import sqlite3
import os
import socket

app = Flask(__name__)

# In-memory SQLite for demo
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT, ssn TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'alice@example.com', 'admin', '123-45-6789')")
    conn.execute("INSERT INTO users VALUES (2, 'bob', 'bob@example.com', 'user', '987-65-4321')")
    conn.execute("INSERT INTO users VALUES (3, 'charlie', 'charlie@example.com', 'user', '555-12-3456')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({"status": "ok", "message": "EvidenceGuardian Demo Target"})


@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    """IDOR-vulnerable endpoint: no authorization check on user_id."""
    conn = sqlite3.connect(DB_PATH)
    user = conn.execute("SELECT id, username, email, role, ssn FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return jsonify({"id": user[0], "username": user[1], "email": user[2], "role": user[3], "ssn": user[4]})
    return jsonify({"error": "User not found"}), 404


@app.route("/api/fetch")
def fetch_url():
    """SSRF-vulnerable endpoint: fetches user-supplied URL.
    
    For internal addresses, returns simulated AWS metadata.
    For external URLs, makes actual request with timeout.
    """
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400

    # Simulate internal address detection with realistic AWS metadata response
    if "169.254" in url or "127.0.0.1" in url or "localhost" in url:
        return jsonify({
            "accountId": "123456789012",
            "availabilityZone": "us-east-1a",
            "imageId": "ami-0abcdef1234567890",
            "instanceId": "i-0abcdef1234567890a",
            "instanceType": "t2.micro",
            "region": "us-east-1"
        }), 200

    # External URL — make actual request with timeout to prevent hangs
    import urllib.request
    try:
        # Set a timeout to prevent hanging
        socket.setdefaulttimeout(5)
        req = urllib.request.Request(url, headers={"User-Agent": "EvidenceGuardian-Demo"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read()[:500]
            return jsonify({"status": "fetched", "url": url, "content_preview": content.decode("utf-8", errors="replace")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        socket.setdefaulttimeout(None)


@app.route("/search")
def search():
    """XSS-vulnerable endpoint: reflects search query without encoding."""
    q = request.args.get("q", "")
    response = make_response(jsonify({"query": q, "results": [], "html": f"<div>Results for: {q}</div>"}))
    response.headers["Content-Type"] = "application/json"
    return response


@app.route("/api/login", methods=["GET", "POST"])
def login():
    """SQLi-vulnerable endpoint: string concatenation in SQL.
    
    Accepts username via query param OR form data.
    Supports SQLi via id parameter too.
    """
    username = request.args.get("username", "") or request.form.get("username", "")
    password = request.args.get("password", "") or request.form.get("password", "")
    user_id = request.args.get("id", "") or request.args.get("user", "") or request.args.get("email", "")

    # Support SQLi via id parameter too
    if user_id:
        try:
            query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
            conn = sqlite3.connect(DB_PATH)
            user = conn.execute(query).fetchone()
            conn.close()
            if user:
                return jsonify({"status": "found", "user": {"id": user[0], "username": user[1], "email": user[2], "role": user[3]}})
            return jsonify({"error": "User not found"}), 404
        except Exception as e:
            return jsonify({"error": f"SQL error: {str(e)}"}), 500

    # Original SQLi via username/password
    if not username:
        return jsonify({"error": "username or id parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    try:
        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
    except Exception as e:
        return jsonify({"error": f"SQL error: {str(e)}"}), 500
    finally:
        conn.close()
    if user:
        return jsonify({"status": "logged_in", "user": {"id": user[0], "username": user[1], "email": user[2], "role": user[3]}})
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


@app.route("/rest/products/search")
def product_search():
    """Juice Shop-style search endpoint (XSS vulnerable)."""
    q = request.args.get("q", "")
    return jsonify({"data": [{"name": f"Product matching {q}", "description": f"<p>Results for: {q}</p>"}]})


@app.route("/rest/user/login")
def rest_login():
    """Juice Shop-style login endpoint (SQLi vulnerable)."""
    email = request.args.get("email", "") or request.args.get("username", "")
    password = request.args.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    try:
        query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
    except Exception as e:
        return jsonify({"error": f"SQL error: {str(e)}"}), 500
    finally:
        conn.close()
    if user:
        return jsonify({"authentication": {"token": "fake-jwt-token", "user": {"id": user[0], "email": user[1]}}})
    return jsonify({"error": "Invalid email or password"}), 401


@app.route("/.env.backup")
def env_backup():
    """Exposed .env backup file."""
    return """
DB_HOST=localhost
DB_PORT=5432
DB_NAME=juice_shop
DB_USER=admin
DB_PASSWORD=super_secret_password
API_KEY=akia1234567890abcdef
SECRET_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
""", 200, {"Content-Type": "text/plain"}


@app.route("/ftp/<path:filename>")
def ftp_file(filename):
    """FTP file access."""
    if "acquisitions" in filename:
        return """
# Confidential Acquisitions Document
## Q4 2024 Plans
- Acquire competitor XYZ for $50M
- New product line: Juice Shop Premium
- Internal only - do not distribute
""", 200, {"Content-Type": "text/plain"}
    return jsonify({"error": "Not found"}), 404


@app.route("/ftp/")
def ftp_index():
    """FTP directory listing."""
    return """
<!DOCTYPE html>
<html>
<head><title>listing directory /ftp/</title></head>
<body>
<h1>Index of /ftp/</h1>
<ul>
<li><a href="acquisitions.md">acquisitions.md</a></li>
<li><a href="coupons_2013.md.bak">coupons_2013.md.bak</a></li>
<li><a href="legal.md">legal.md</a></li>
</ul>
</body>
</html>
""", 200


@app.route("/metrics")
def metrics():
    """Debug metrics endpoint."""
    return jsonify({
        "cpu_usage": 45.2,
        "memory_usage": 67.8,
        "active_connections": 12,
        "environment": "development",
        "debug_mode": True,
    })


@app.route("/security.txt")
def security_txt():
    """Security.txt file."""
    return """
Contact: security@juice-sh.op
Acknowledgments: /#/score-board
""", 200


if __name__ == "__main__":
    init_db()
    print("EvidenceGuardian Demo Server")
    print("WARNING: This app is intentionally vulnerable. Do NOT expose to public networks.")
    print("Starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)