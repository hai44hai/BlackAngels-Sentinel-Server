import os
import json
import time
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

APP = Flask(__name__)
DB_PATH = os.environ.get("BA_SENTINEL_DB", "sentinel_admin.db")
ONLINE_SECONDS = 45


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        device TEXT,
        version TEXT,
        last_seen REAL NOT NULL,
        last_seen_iso TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        running INTEGER NOT NULL DEFAULT 0,
        gate_states TEXT NOT NULL DEFAULT '{}',
        goldfields_score REAL NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        event_type TEXT NOT NULL,
        gate_name TEXT,
        details TEXT,
        created_at TEXT NOT NULL
    );
    """)

    # Bootstrap admin from environment.
    admin_user = os.environ.get("BA_ADMIN_USER", "blackangels")
    admin_pass = os.environ.get("BA_ADMIN_PASSWORD", "famliyonly1")

    if admin_pass:
        exists = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (admin_user,)
        ).fetchone()

        if not exists:
            conn.execute(
                """
                INSERT INTO users
                (username, password_hash, role, enabled, created_at)
                VALUES (?, ?, 'admin', 1, ?)
                """,
                (
                    admin_user,
                    generate_password_hash(admin_pass),
                    now_iso()
                )
            )
        else:
            # Keep the bootstrap admin usable even if the database already
            # existed with an older password.
            conn.execute(
                """
                UPDATE users
                SET password_hash=?, role='admin', enabled=1
                WHERE username=?
                """,
                (
                    generate_password_hash(admin_pass),
                    admin_user
                )
            )

    conn.commit()
    conn.close()


def bearer():
    value = request.headers.get("Authorization", "")
    if value.startswith("Bearer "):
        return value[7:].strip()
    return None


def current_session():
    token = bearer()
    if not token:
        return None

    conn = db()
    row = conn.execute(
        """
        SELECT
            s.*,
            u.username,
            u.role,
            u.enabled
        FROM sessions s
        JOIN users u ON u.id=s.user_id
        WHERE s.token=?
        """,
        (token,)
    ).fetchone()
    conn.close()
    return row


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        row = current_session()
        if not row or row["revoked"] or not row["enabled"]:
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        request.auth_session = row
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn):
    @wraps(fn)
    @require_auth
    def wrapper(*args, **kwargs):
        if request.auth_session["role"] != "admin":
            return jsonify({"ok": False, "error": "admin required"}), 403
        return fn(*args, **kwargs)
    return wrapper


@APP.get("/")
def index():
    return jsonify({
        "ok": True,
        "service": "BlackAngels Sentinel Admin Server"
    })


@APP.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if (
        not user
        or not user["enabled"]
        or not check_password_hash(user["password_hash"], password)
    ):
        conn.close()
        return jsonify({"ok": False, "error": "invalid login"}), 401

    token = secrets.token_urlsafe(32)

    conn.execute(
        """
        INSERT INTO sessions
        (token, user_id, device, version, last_seen, last_seen_iso, revoked)
        VALUES (?, ?, ?, ?, ?, ?, 0)
        """,
        (
            token,
            user["id"],
            str(data.get("device", ""))[:250],
            str(data.get("version", ""))[:100],
            time.time(),
            now_iso()
        )
    )
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "token": token,
        "username": user["username"],
        "role": user["role"]
    })


@APP.post("/api/logout")
@require_auth
def logout():
    token = bearer()
    conn = db()
    conn.execute(
        "UPDATE sessions SET revoked=1 WHERE token=?",
        (token,)
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@APP.post("/api/heartbeat")
@require_auth
def heartbeat():
    data = request.get_json(silent=True) or {}
    token = bearer()

    conn = db()
    conn.execute(
        """
        UPDATE sessions
        SET
            device=?,
            version=?,
            last_seen=?,
            last_seen_iso=?,
            running=?,
            gate_states=?,
            goldfields_score=?
        WHERE token=?
        """,
        (
            str(data.get("device", ""))[:250],
            str(data.get("version", ""))[:100],
            time.time(),
            now_iso(),
            1 if data.get("running") else 0,
            json.dumps(data.get("gate_states", {})),
            float(data.get("goldfields_score", 0.0)),
            token
        )
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@APP.post("/api/events")
@require_auth
def add_event():
    data = request.get_json(silent=True) or {}
    row = request.auth_session

    conn = db()
    conn.execute(
        """
        INSERT INTO events
        (user_id, username, event_type, gate_name, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            row["user_id"],
            row["username"],
            str(data.get("event_type", ""))[:100],
            str(data.get("gate_name", ""))[:100],
            str(data.get("details", ""))[:500],
            now_iso()
        )
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@APP.get("/api/admin/users")
@require_admin
def admin_users():
    conn = db()

    users = conn.execute(
        "SELECT id, username, role, enabled, created_at FROM users ORDER BY username"
    ).fetchall()

    result = []
    cutoff = time.time() - ONLINE_SECONDS

    for user in users:
        session = conn.execute(
            """
            SELECT *
            FROM sessions
            WHERE user_id=? AND revoked=0
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (user["id"],)
        ).fetchone()

        online = bool(
            user["enabled"]
            and session
            and session["last_seen"] >= cutoff
        )

        result.append({
            "username": user["username"],
            "role": user["role"],
            "enabled": bool(user["enabled"]),
            "online": online,
            "device": session["device"] if session else "",
            "last_seen": session["last_seen_iso"] if session else "",
            "version": session["version"] if session else "",
            "running": bool(session["running"]) if session else False
        })

    conn.close()
    return jsonify({"ok": True, "users": result})


@APP.post("/api/admin/users")
@require_admin
def create_user():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    role = str(data.get("role", "user")).strip().lower()

    if not username or len(password) < 4:
        return jsonify({
            "ok": False,
            "error": "username required and password must be at least 4 characters"
        }), 400

    if role not in ("user", "admin"):
        role = "user"

    conn = db()
    try:
        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, role, enabled, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (
                username,
                generate_password_hash(password),
                role,
                now_iso()
            )
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"ok": False, "error": "username already exists"}), 409

    conn.close()
    return jsonify({"ok": True})


@APP.post("/api/admin/users/<username>/toggle")
@require_admin
def toggle_user(username):
    if username == request.auth_session["username"]:
        return jsonify({"ok": False, "error": "cannot disable yourself"}), 400

    conn = db()
    row = conn.execute(
        "SELECT enabled FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "user not found"}), 404

    new_value = 0 if row["enabled"] else 1
    conn.execute(
        "UPDATE users SET enabled=? WHERE username=?",
        (new_value, username)
    )

    if new_value == 0:
        conn.execute(
            """
            UPDATE sessions SET revoked=1
            WHERE user_id=(SELECT id FROM users WHERE username=?)
            """,
            (username,)
        )

    conn.commit()
    conn.close()
    return jsonify({"ok": True, "enabled": bool(new_value)})


@APP.post("/api/admin/users/<username>/disconnect")
@require_admin
def disconnect_user(username):
    conn = db()
    conn.execute(
        """
        UPDATE sessions SET revoked=1
        WHERE user_id=(SELECT id FROM users WHERE username=?)
        """,
        (username,)
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@APP.post("/api/admin/users/<username>/password")
@require_admin
def change_password(username):
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))

    if len(password) < 4:
        return jsonify({"ok": False, "error": "password too short"}), 400

    conn = db()
    cur = conn.execute(
        "UPDATE users SET password_hash=? WHERE username=?",
        (generate_password_hash(password), username)
    )
    conn.commit()
    conn.close()

    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "user not found"}), 404

    return jsonify({"ok": True})


@APP.get("/api/admin/events")
@require_admin
def admin_events():
    conn = db()
    rows = conn.execute(
        """
        SELECT username, event_type, gate_name, details, created_at
        FROM events
        ORDER BY id DESC
        LIMIT 300
        """
    ).fetchall()
    conn.close()

    return jsonify({
        "ok": True,
        "events": [dict(row) for row in rows]
    })


init_db()

if __name__ == "__main__":
    print("BlackAngels Sentinel Admin Server")
    print("Bootstrap admin:", os.environ.get("BA_ADMIN_USER", "blackangels"))
    print("Admin credentials initialized.")

    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
