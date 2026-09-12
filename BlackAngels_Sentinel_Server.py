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

# =========================================================
# STORAGE
# =========================================================
# IMPORTANT:
# - On Render Free, the local filesystem is temporary.
# - If a persistent disk is mounted at /var/data, this server automatically
#   stores the database there.
# - You can also override the path with BA_SENTINEL_DB.

if os.environ.get("BA_SENTINEL_DB"):
    DB_PATH = os.environ["BA_SENTINEL_DB"]
elif os.path.isdir("/var/data"):
    DB_PATH = "/var/data/sentinel_admin.db"
else:
    DB_PATH = "sentinel_admin.db"

ONLINE_SECONDS = 45


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
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

        CREATE TABLE IF NOT EXISTS app_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            config_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        );
        """
    )

    # Bootstrap ADMIN ONLY when it does not exist.
    # After creation, changing the admin password from the ADMIN application
    # is permanent and is NOT overwritten on server restart/deploy.
    admin_user = os.environ.get("BA_ADMIN_USER", "blackangels").strip()
    admin_pass = os.environ.get("BA_ADMIN_PASSWORD", "")

    exists = conn.execute(
        "SELECT id FROM users WHERE username=?",
        (admin_user,),
    ).fetchone()

    if not exists:
        if not admin_pass:
            conn.close()
            raise RuntimeError(
                "BA_ADMIN_PASSWORD is required the first time the database is created"
            )

        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, role, enabled, created_at)
            VALUES (?, ?, 'admin', 1, ?)
            """,
            (
                admin_user,
                generate_password_hash(admin_pass),
                now_iso(),
            ),
        )

    # Make sure the bootstrap account keeps admin privileges, but DO NOT touch
    # its password after it already exists.
    conn.execute(
        "UPDATE users SET role='admin', enabled=1 WHERE username=?",
        (admin_user,),
    )

    row = conn.execute("SELECT id FROM app_config WHERE id=1").fetchone()
    if not row:
        default_config = {
            "gate_names": {},
            "map_names": {},
            "active_map": "Goldfields",
        }
        conn.execute(
            "INSERT INTO app_config (id, config_json, updated_at) VALUES (1, ?, ?)",
            (json.dumps(default_config), now_iso()),
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
        (token,),
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


# =========================================================
# BASIC / CONFIG
# =========================================================

@APP.get("/")
def index():
    return jsonify(
        {
            "ok": True,
            "service": "BlackAngels Sentinel Admin Server",
            "storage": DB_PATH,
        }
    )


def _load_config(conn):
    row = conn.execute(
        "SELECT config_json FROM app_config WHERE id=1"
    ).fetchone()
    if not row:
        return {
            "gate_names": {},
            "map_names": {},
            "active_map": "Goldfields",
        }
    try:
        data = json.loads(row["config_json"] or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


@APP.get("/api/config")
def get_config():
    conn = db()
    cfg = _load_config(conn)
    conn.close()
    return jsonify({"ok": True, "config": cfg})


@APP.post("/api/admin/config")
@require_admin
def update_config():
    patch = request.get_json(silent=True) or {}
    if not isinstance(patch, dict):
        return jsonify({"ok": False, "error": "invalid config"}), 400

    conn = db()
    cfg = _load_config(conn)

    # Merge only known config sections used by Sentinel.
    if isinstance(patch.get("gate_names"), dict):
        current = cfg.get("gate_names")
        if not isinstance(current, dict):
            current = {}
        current.update({str(k): str(v) for k, v in patch["gate_names"].items()})
        cfg["gate_names"] = current

    if isinstance(patch.get("map_names"), dict):
        current = cfg.get("map_names")
        if not isinstance(current, dict):
            current = {}
        current.update({str(k): str(v) for k, v in patch["map_names"].items()})
        cfg["map_names"] = current

    if "active_map" in patch:
        cfg["active_map"] = str(patch.get("active_map", "Goldfields"))

    conn.execute(
        "UPDATE app_config SET config_json=?, updated_at=? WHERE id=1",
        (json.dumps(cfg, ensure_ascii=False), now_iso()),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "config": cfg})


# =========================================================
# AUTH
# =========================================================

@APP.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (username,),
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
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()

    return jsonify(
        {
            "ok": True,
            "token": token,
            "username": user["username"],
            "role": user["role"],
        }
    )


@APP.post("/api/logout")
@require_auth
def logout():
    token = bearer()
    conn = db()
    conn.execute("UPDATE sessions SET revoked=1 WHERE token=?", (token,))
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
            token,
        ),
    )
    conn.commit()

    cfg = _load_config(conn)
    conn.close()
    return jsonify({"ok": True, "config": cfg})


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
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# =========================================================
# ADMIN - USERS
# =========================================================

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
            (user["id"],),
        ).fetchone()

        online = bool(
            user["enabled"] and session and session["last_seen"] >= cutoff
        )

        result.append(
            {
                "username": user["username"],
                "role": user["role"],
                "enabled": bool(user["enabled"]),
                "online": online,
                "device": session["device"] if session else "",
                "last_seen": session["last_seen_iso"] if session else "",
                "version": session["version"] if session else "",
                "running": bool(session["running"]) if session else False,
            }
        )

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
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "username required and password must be at least 4 characters",
                }
            ),
            400,
        )

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
                now_iso(),
            ),
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
        (username,),
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "user not found"}), 404

    new_value = 0 if row["enabled"] else 1
    conn.execute(
        "UPDATE users SET enabled=? WHERE username=?",
        (new_value, username),
    )

    if new_value == 0:
        conn.execute(
            """
            UPDATE sessions SET revoked=1
            WHERE user_id=(SELECT id FROM users WHERE username=?)
            """,
            (username,),
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
        (username,),
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
        (generate_password_hash(password), username),
    )

    # Revoke other sessions for this user so the new password takes effect cleanly.
    conn.execute(
        """
        UPDATE sessions SET revoked=1
        WHERE user_id=(SELECT id FROM users WHERE username=?)
          AND token<>?
        """,
        (username, bearer() or ""),
    )

    conn.commit()
    conn.close()

    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "user not found"}), 404

    return jsonify({"ok": True})


# =========================================================
# ADMIN - EVENTS
# =========================================================

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

    return jsonify(
        {
            "ok": True,
            "events": [dict(row) for row in rows],
        }
    )


# =========================================================
# STARTUP
# =========================================================

init_db()

if __name__ == "__main__":
    print("BlackAngels Sentinel Admin Server")
    print("Database:", DB_PATH)
    print("Bootstrap admin:", os.environ.get("BA_ADMIN_USER", "blackangels"))
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
