
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import uuid
import os
import functools
import pandas 
import nummpy

# -----------------------------------------------------
app = Flask(__name__)
app.secret_key = "super-secret-key-change-this"
app.permanent_session_lifetime = timedelta(minutes=90)

DATABASE = "anticheat.db"
MAX_VIOLATIONS = 3
TEST_DURATION_MINUTES = 30

# =====================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    # Test sessions
    cur.execute("""
    CREATE TABLE IF NOT EXISTS test_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_token TEXT,
        start_time TEXT,
        end_time TEXT,
        violations INTEGER DEFAULT 0,
        terminated INTEGER DEFAULT 0,
        ip TEXT,
        user_agent TEXT
    )
    """)

    # Violation logs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS violations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        type TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

# =====================================================
# Security Helpers
# =====================================================

def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped

def bind_client(session_row):
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")

    if session_row["ip"] != ip or session_row["user_agent"] != ua:
        abort(403, "Session hijack detected")

# =====================================================
# Routes – Auth
# =====================================================

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        return "Invalid credentials", 401

    return """
    <h2>Login</h2>
    <form method="post">
      <input name="email" placeholder="Email"><br>
      <input name="password" type="password" placeholder="Password"><br>
      <button>Login</button>
    </form>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =====================================================
# Routes – Candidate
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    return """
    <h2>Candidate Dashboard</h2>
    <p>Welcome</p>
    <a href="/start-test">Start Test</a>
    <br><a href="/logout">Logout</a>
    """

@app.route("/start-test")
@login_required
def start_test():
    token = str(uuid.uuid4())
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")

    conn = get_db()
    conn.execute("""
    INSERT INTO test_sessions 
    (user_id, session_token, start_time, ip, user_agent)
    VALUES (?, ?, ?, ?, ?)
    """, (
        session["user_id"],
        token,
        datetime.utcnow().isoformat(),
        ip,
        ua
    ))
    conn.commit()
    conn.close()

    session["test_token"] = token
    return redirect(url_for("test_page"))

@app.route("/test")
@login_required
def test_page():
    token = session.get("test_token")
    if not token:
        return redirect(url_for("dashboard"))

    return render_template("test.html")

# =====================================================
# API – Anti Cheat Events
# =====================================================

@app.route("/api/violation", methods=["POST"])
@login_required
def log_violation():
    data = request.json
    vtype = data.get("type")

    token = session.get("test_token")
    if not token:
        abort(403)

    conn = get_db()
    ts = conn.execute("""
    SELECT * FROM test_sessions 
    WHERE session_token = ?
    """, (token,)).fetchone()

    if not ts:
        abort(404)

    bind_client(ts)

    if ts["terminated"]:
        abort(403)

    new_count = ts["violations"] + 1

    conn.execute("""
    INSERT INTO violations (session_id, type, timestamp)
    VALUES (?, ?, ?)
    """, (
        ts["id"],
        vtype,
        datetime.utcnow().isoformat()
    ))

    terminate = 1 if new_count >= MAX_VIOLATIONS else 0

    conn.execute("""
    UPDATE test_sessions
    SET violations = ?, terminated = ?
    WHERE id = ?
    """, (
        new_count,
        terminate,
        ts["id"]
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "violations": new_count,
        "terminated": bool(terminate)
    })

@app.route("/api/status")
@login_required
def test_status():
    token = session.get("test_token")
    if not token:
        abort(403)

    conn = get_db()
    ts = conn.execute("""
    SELECT * FROM test_sessions WHERE session_token = ?
    """, (token,)).fetchone()
    conn.close()

    if not ts:
        abort(404)

    start = datetime.fromisoformat(ts["start_time"])
    elapsed = (datetime.utcnow() - start).total_seconds() / 60

    expired = elapsed >= TEST_DURATION_MINUTES

    if expired and not ts["end_time"]:
        conn = get_db()
        conn.execute("""
        UPDATE test_sessions SET end_time = ?
        WHERE id = ?
        """, (datetime.utcnow().isoformat(), ts["id"]))
        conn.commit()
        conn.close()

    return jsonify({
        "violations": ts["violations"],
        "terminated": bool(ts["terminated"]),
        "time_left": max(0, TEST_DURATION_MINUTES - elapsed)
    })

# =====================================================
# Admin Routes
# =====================================================

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()
    sessions = conn.execute("""
    SELECT ts.id, u.name, ts.violations, ts.terminated, ts.start_time
    FROM test_sessions ts
    JOIN users u ON u.id = ts.user_id
    ORDER BY ts.id DESC
    """).fetchall()
    conn.close()

    html = "<h2>Admin Dashboard</h2><ul>"
    for s in sessions:
        html += f"<li>{s['name']} | Violations: {s['violations']} | Terminated: {s['terminated']}</li>"
    html += "</ul>"
    return html

# =====================================================
# Setup Default Admin
# =====================================================

def seed_admin():
    conn = get_db()
    admin = conn.execute(
        "SELECT * FROM users WHERE role='admin'"
    ).fetchone()

    if not admin:
        conn.execute("""
        INSERT INTO users (name, email, password, role)
        VALUES (?, ?, ?, ?)
        """, (
            "Admin",
            "admin@system.com",
            generate_password_hash("admin123"),
            "admin"
        ))
        conn.commit()

    conn.close()

# =====================================================
# App Start
# =====================================================

if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
        seed_admin()

    app.run(debug=True)
