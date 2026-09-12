import os
import json
import time
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.errors
except Exception:
    psycopg2 = None

APP = Flask(__name__)

# =========================================================
# STORAGE
# =========================================================
# Primary storage:
#   DATABASE_URL -> PostgreSQL / Neon (persistent)
# Fallback storage:
#   BA_SENTINEL_DB or local SQLite (only used when DATABASE_URL is absent)
#
# IMPORTANT: never hard-code the Neon connection string in this file.
# Put it in Render -> Environment as DATABASE_URL.

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

if os.environ.get("BA_SENTINEL_DB"):
    SQLITE_PATH = os.environ["BA_SENTINEL_DB"]
elif os.path.isdir("/var/data"):
    SQLITE_PATH = "/var/data/sentinel_admin.db"
else:
    SQLITE_PATH = "sentinel_admin.db"

USE_POSTGRES = bool(DATABASE_URL)
ONLINE_SECONDS = 45


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class DBResult:
    def __init__(self, cursor):
        self.cursor = cursor

    @property
    def rowcount(self):
        return self.cursor.rowcount

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        return row

    def fetchall(self):
        return self.cursor.fetchall()


class DBConnection:
    def __init__(self):
        self.is_postgres = USE_POSTGRES

        if self.is_postgres:
            if psycopg2 is None:
                raise RuntimeError(
                    "DATABASE_URL is set but psycopg2 is not installed. "
                    "Install psycopg2-binary from requirements.txt."
                )
            self.conn = psycopg2.connect(
                DATABASE_URL,
                connect_timeout=15,
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
            self.conn.autocommit = False
        else:
            self.conn = sqlite3.connect(SQLITE_PATH, timeout=20)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")

    def _sql(self, sql):
        # Existing server queries use SQLite-style ? placeholders.
        # PostgreSQL/psycopg2 uses %s.
        if self.is_postgres:
            return sql.replace("?", "%s")
        return sql

    def execute(self, sql, params=()):
        cur = self.conn.cursor()
        cur.execute(self._sql(sql), params)
        return DBResult(cur)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


def db():
    return DBConnection()


def init_db():
    conn = db()
    try:
        if conn.is_postgres:
            statements = [
                """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id),
                    device TEXT,
                    version TEXT,
                    last_seen DOUBLE PRECISION NOT NULL,
                    last_seen_iso TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    running INTEGER NOT NULL DEFAULT 0,
                    gate_states TEXT NOT NULL DEFAULT '{}',
                    goldfields_score DOUBLE PRECISION NOT NULL DEFAULT 0
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS events (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT,
                    username TEXT,
                    event_type TEXT NOT NULL,
                    gate_name TEXT,
                    details TEXT,
                    created_at TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS app_config (
                    id INTEGER PRIMARY KEY,
                    config_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL,
                    CHECK (id = 1)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_sessions_user_last_seen ON sessions(user_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_events_id_desc ON events(id DESC)",
            ]
            for stmt in statements:
                conn.execute(stmt)
        else:
            conn.conn.executescript(
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

        # Bootstrap admin only if it doesn't already exist.
        # Once created, changing its password from the ADMIN app is permanent.
        admin_user = os.environ.get("BA_ADMIN_USER", "blackangels").strip()
        admin_pass = os.environ.get("BA_ADMIN_PASSWORD", "")

        exists = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (admin_user,),
        ).fetchone()

        if not exists:
            if not admin_pass:
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

        # Keep bootstrap account enabled/admin, but never overwrite its password.
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
                "updates": {
                    "published": False,
                    "latest_version": "V43",
                    "minimum_version": "V43",
                    "force_update": False,
                    "download_url": "",
                    "sha256": "",
                    "message": "",
                },
            }
            conn.execute(
                "INSERT INTO app_config (id, config_json, updated_at) VALUES (1, ?, ?)",
                (json.dumps(default_config), now_iso()),
            )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
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
    try:
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
        return row
    finally:
        conn.close()


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
            "storage": "postgresql" if USE_POSTGRES else "sqlite-fallback",
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
            "updates": {
                "published": False,
                "latest_version": "V43",
                "minimum_version": "V43",
                "force_update": False,
                "download_url": "",
                "sha256": "",
                "message": "",
            },
        }
    try:
        data = json.loads(row["config_json"] or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _version_tuple(value):
    """Convert V44 / 44.1 / USER_V43_... into a comparable integer tuple."""
    import re
    nums = re.findall(r"\d+", str(value or ""))
    if not nums:
        return (0,)
    return tuple(int(x) for x in nums[:4])


def _update_settings(cfg):
    raw = cfg.get("updates") if isinstance(cfg, dict) else None
    if not isinstance(raw, dict):
        raw = {}
    return {
        "published": bool(raw.get("published", False)),
        "latest_version": str(raw.get("latest_version", "V43") or "V43"),
        "minimum_version": str(raw.get("minimum_version", "V43") or "V43"),
        "force_update": bool(raw.get("force_update", False)),
        "download_url": str(raw.get("download_url", "") or ""),
        "sha256": str(raw.get("sha256", "") or "").strip().lower(),
        "message": str(raw.get("message", "") or ""),
    }


@APP.get("/api/version")
def public_version():
    conn = db()
    try:
        cfg = _load_config(conn)
        return jsonify({"ok": True, "update": _update_settings(cfg)})
    finally:
        conn.close()


@APP.get("/api/admin/update-config")
@require_admin
def admin_get_update_config():
    conn = db()
    try:
        cfg = _load_config(conn)
        return jsonify({"ok": True, "update": _update_settings(cfg)})
    finally:
        conn.close()


@APP.post("/api/admin/update-config")
@require_admin
def admin_set_update_config():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "invalid update config"}), 400

    latest = str(data.get("latest_version", "V43") or "V43").strip()
    minimum = str(data.get("minimum_version", "V43") or "V43").strip()
    download_url = str(data.get("download_url", "") or "").strip()
    sha256 = str(data.get("sha256", "") or "").strip().lower()
    message = str(data.get("message", "") or "")[:1000]
    published = bool(data.get("published", False))
    force_update = bool(data.get("force_update", False))

    if not latest or not minimum:
        return jsonify({"ok": False, "error": "latest/minimum version required"}), 400
    if _version_tuple(minimum) > _version_tuple(latest):
        return jsonify({"ok": False, "error": "minimum version cannot be newer than latest version"}), 400
    if published and not download_url:
        return jsonify({"ok": False, "error": "download URL required before publishing"}), 400
    if sha256 and (len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256)):
        return jsonify({"ok": False, "error": "sha256 must be 64 hexadecimal characters"}), 400

    update_cfg = {
        "published": published,
        "latest_version": latest,
        "minimum_version": minimum,
        "force_update": force_update,
        "download_url": download_url,
        "sha256": sha256,
        "message": message,
    }

    conn = db()
    try:
        cfg = _load_config(conn)
        cfg["updates"] = update_cfg
        conn.execute(
            "UPDATE app_config SET config_json=?, updated_at=? WHERE id=1",
            (json.dumps(cfg, ensure_ascii=False), now_iso()),
        )
        conn.commit()
        return jsonify({"ok": True, "update": update_cfg})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@APP.get("/api/config")
def get_config():
    conn = db()
    try:
        cfg = _load_config(conn)
        return jsonify({"ok": True, "config": cfg})
    finally:
        conn.close()


@APP.post("/api/admin/config")
@require_admin
def update_config():
    patch = request.get_json(silent=True) or {}
    if not isinstance(patch, dict):
        return jsonify({"ok": False, "error": "invalid config"}), 400

    conn = db()
    try:
        cfg = _load_config(conn)

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
        return jsonify({"ok": True, "config": cfg})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# =========================================================
# AUTH
# =========================================================

@APP.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    conn = db()
    try:
        client_version = str(data.get("version", ""))
        # ADMIN builds stay able to sign in so the owner cannot lock himself out.
        if not client_version.upper().startswith("ADMIN_"):
            cfg = _load_config(conn)
            update_cfg = _update_settings(cfg)
            if update_cfg["published"]:
                required = (
                    update_cfg["latest_version"]
                    if update_cfg["force_update"]
                    else update_cfg["minimum_version"]
                )
                if _version_tuple(client_version) < _version_tuple(required):
                    return jsonify({
                        "ok": False,
                        "error": "update required",
                        "update_required": True,
                        "update": update_cfg,
                    }), 426

        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,),
        ).fetchone()

        if (
            not user
            or not user["enabled"]
            or not check_password_hash(user["password_hash"], password)
        ):
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

        return jsonify(
            {
                "ok": True,
                "token": token,
                "username": user["username"],
                "role": user["role"],
            }
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@APP.post("/api/logout")
@require_auth
def logout():
    token = bearer()
    conn = db()
    try:
        conn.execute("UPDATE sessions SET revoked=1 WHERE token=?", (token,))
        conn.commit()
        return jsonify({"ok": True})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@APP.post("/api/heartbeat")
@require_auth
def heartbeat():
    data = request.get_json(silent=True) or {}
    token = bearer()

    conn = db()
    try:
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
        return jsonify({"ok": True, "config": cfg})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@APP.post("/api/events")
@require_auth
def add_event():
    data = request.get_json(silent=True) or {}
    row = request.auth_session

    conn = db()
    try:
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
        return jsonify({"ok": True})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# =========================================================
# ADMIN - USERS
# =========================================================

@APP.get("/api/admin/users")
@require_admin
def admin_users():
    conn = db()
    try:
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

        return jsonify({"ok": True, "users": result})
    finally:
        conn.close()


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
    except Exception as e:
        conn.rollback()
        # Duplicate username: SQLite and PostgreSQL report different exception types.
        duplicate = isinstance(e, sqlite3.IntegrityError)
        if psycopg2 is not None and isinstance(e, psycopg2.IntegrityError):
            duplicate = True
        if duplicate:
            return jsonify({"ok": False, "error": "username already exists"}), 409
        raise
    finally:
        conn.close()

    return jsonify({"ok": True})


@APP.post("/api/admin/users/<username>/toggle")
@require_admin
def toggle_user(username):
    if username == request.auth_session["username"]:
        return jsonify({"ok": False, "error": "cannot disable yourself"}), 400

    conn = db()
    try:
        row = conn.execute(
            "SELECT enabled FROM users WHERE username=?",
            (username,),
        ).fetchone()

        if not row:
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
        return jsonify({"ok": True, "enabled": bool(new_value)})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@APP.post("/api/admin/users/<username>/disconnect")
@require_admin
def disconnect_user(username):
    conn = db()
    try:
        conn.execute(
            """
            UPDATE sessions SET revoked=1
            WHERE user_id=(SELECT id FROM users WHERE username=?)
            """,
            (username,),
        )
        conn.commit()
        return jsonify({"ok": True})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@APP.delete("/api/admin/users/<username>")
@require_admin
def delete_user(username):
    if username == request.auth_session["username"]:
        return jsonify({"ok": False, "error": "cannot delete yourself"}), 400

    conn = db()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (username,),
        ).fetchone()

        if not row:
            return jsonify({"ok": False, "error": "user not found"}), 404

        user_id = row["id"]

        conn.execute(
            "DELETE FROM sessions WHERE user_id=?",
            (user_id,),
        )
        conn.execute(
            "DELETE FROM users WHERE id=?",
            (user_id,),
        )
        conn.commit()
        return jsonify({"ok": True})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@APP.post("/api/admin/users/<username>/username")
@require_admin
def change_username(username):
    if username == request.auth_session["username"]:
        return jsonify({"ok": False, "error": "cannot rename yourself while logged in"}), 400

    data = request.get_json(silent=True) or {}
    new_username = str(data.get("username", "")).strip()

    if len(new_username) < 2:
        return jsonify({"ok": False, "error": "username too short"}), 400
    if len(new_username) > 64:
        return jsonify({"ok": False, "error": "username too long"}), 400

    conn = db()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (username,),
        ).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "user not found"}), 404

        exists = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (new_username,),
        ).fetchone()
        if exists:
            return jsonify({"ok": False, "error": "username already exists"}), 409

        user_id = row["id"]
        conn.execute(
            "UPDATE users SET username=? WHERE id=?",
            (new_username, user_id),
        )
        conn.execute(
            "UPDATE sessions SET revoked=1 WHERE user_id=?",
            (user_id,),
        )
        conn.commit()
        return jsonify({"ok": True, "username": new_username})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@APP.post("/api/admin/users/<username>/password")
@require_admin
def change_password(username):
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))

    if len(password) < 4:
        return jsonify({"ok": False, "error": "password too short"}), 400

    conn = db()
    try:
        cur = conn.execute(
            "UPDATE users SET password_hash=? WHERE username=?",
            (generate_password_hash(password), username),
        )

        conn.execute(
            """
            UPDATE sessions SET revoked=1
            WHERE user_id=(SELECT id FROM users WHERE username=?)
              AND token<>?
            """,
            (username, bearer() or ""),
        )

        conn.commit()

        if cur.rowcount == 0:
            return jsonify({"ok": False, "error": "user not found"}), 404

        return jsonify({"ok": True})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# =========================================================
# ADMIN - EVENTS
# =========================================================

@APP.get("/api/admin/events")
@require_admin
def admin_events():
    conn = db()
    try:
        rows = conn.execute(
            """
            SELECT username, event_type, gate_name, details, created_at
            FROM events
            ORDER BY id DESC
            LIMIT 300
            """
        ).fetchall()

        return jsonify(
            {
                "ok": True,
                "events": [dict(row) for row in rows],
            }
        )
    finally:
        conn.close()


# =========================================================
# STARTUP
# =========================================================

init_db()

if __name__ == "__main__":
    print("BlackAngels Sentinel Admin Server")
    print("Storage:", "PostgreSQL / Neon" if USE_POSTGRES else "SQLite fallback")
    print("Bootstrap admin:", os.environ.get("BA_ADMIN_USER", "blackangels"))
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
