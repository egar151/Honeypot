import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


DB_PATH = os.path.join(os.path.dirname(__file__), "honeypot.db")


def get_db():
    conn = getattr(request, "_db_conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        setattr(request, "_db_conn", conn)
    return conn


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cur = conn.cursor()
    # requests table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc TEXT NOT NULL,
            ip TEXT,
            remote_port INTEGER,
            local_port INTEGER,
            method TEXT,
            scheme TEXT,
            host TEXT,
            path TEXT,
            query_string TEXT,
            user_agent TEXT,
            referrer TEXT,
            headers_json TEXT,
            content_type TEXT,
            body_snippet TEXT
        );
        """
    )

    # actors table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS actors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            fail_count INTEGER NOT NULL DEFAULT 0,
            repeater_count INTEGER NOT NULL DEFAULT 0,
            first_seen_utc TEXT NOT NULL,
            last_seen_utc TEXT NOT NULL,
            last_attempt_utc TEXT
        );
        """
    )
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_actors_identity ON actors(ip, user_agent);"
    )

    # login_attempts table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER NOT NULL,
            ts_utc TEXT NOT NULL,
            username TEXT,
            password TEXT,
            success INTEGER NOT NULL,
            attempt_number INTEGER NOT NULL,
            repeater INTEGER NOT NULL,
            reason TEXT,
            FOREIGN KEY(actor_id) REFERENCES actors(id) ON DELETE CASCADE
        );
        """
    )

    conn.commit()
    conn.close()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # Use the first IP in XFF chain
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def get_or_create_actor(conn: sqlite3.Connection, ip: str, ua: str) -> sqlite3.Row:
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM actors WHERE ip = ? AND user_agent = ?",
        (ip, ua),
    )
    row = cur.fetchone()
    now = utcnow_iso()
    if row is None:
        cur.execute(
            """
            INSERT INTO actors (ip, user_agent, fail_count, repeater_count, first_seen_utc, last_seen_utc)
            VALUES (?, ?, 0, 0, ?, ?)
            """,
            (ip, ua, now, now),
        )
        conn.commit()
        cur.execute(
            "SELECT * FROM actors WHERE ip = ? AND user_agent = ?",
            (ip, ua),
        )
        row = cur.fetchone()
    else:
        cur.execute(
            "UPDATE actors SET last_seen_utc = ? WHERE id = ?",
            (now, row["id"]),
        )
        conn.commit()
        cur.execute("SELECT * FROM actors WHERE id = ?", (row["id"],))
        row = cur.fetchone()
    return row


def log_request(conn: sqlite3.Connection):
    hdrs = {k: v for k, v in request.headers.items()}
    headers_json = json.dumps(hdrs, separators=(",", ":"))
    try:
        body_raw = request.get_data(cache=True)
    except Exception:
        body_raw = b""
    # Limit to avoid DB bloat
    body_snippet = body_raw[:8192].decode("utf-8", errors="replace") if body_raw else ""

    env = request.environ
    remote_port = None
    local_port = None
    try:
        remote_port = int(env.get("REMOTE_PORT")) if env.get("REMOTE_PORT") else None
    except Exception:
        pass
    try:
        local_port = int(env.get("SERVER_PORT")) if env.get("SERVER_PORT") else None
    except Exception:
        pass

    conn.execute(
        """
        INSERT INTO requests (
            ts_utc, ip, remote_port, local_port, method, scheme, host, path, query_string,
            user_agent, referrer, headers_json, content_type, body_snippet
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            utcnow_iso(),
            client_ip(),
            remote_port,
            local_port,
            request.method,
            request.scheme,
            request.host,
            request.path,
            request.query_string.decode("utf-8", errors="replace") if isinstance(request.query_string, (bytes, bytearray)) else str(request.query_string),
            request.headers.get("User-Agent", ""),
            request.referrer or "",
            headers_json,
            request.headers.get("Content-Type", ""),
            body_snippet,
        ),
    )
    conn.commit()


app = Flask(__name__)
app.secret_key = os.environ.get("HONEYPOT_SECRET", os.urandom(24))


@app.before_request
def _before_request_log():
    conn = get_db()
    log_request(conn)


@app.teardown_request
def _teardown_request(exc):
    conn = getattr(request, "_db_conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        finally:
            setattr(request, "_db_conn", None)


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    conn = get_db()
    ip = client_ip()
    ua = request.headers.get("User-Agent", "")
    actor = get_or_create_actor(conn, ip, ua)

    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Compute repeater/reset logic
        repeater = False
        now_dt = datetime.now(timezone.utc)
        last_attempt_iso = actor["last_attempt_utc"]
        if last_attempt_iso:
            try:
                last_dt = datetime.fromisoformat(last_attempt_iso)
                if (now_dt - last_dt) >= timedelta(minutes=15):
                    repeater = True
                    conn.execute(
                        "UPDATE actors SET fail_count = 0, repeater_count = repeater_count + 1 WHERE id = ?",
                        (actor["id"],),
                    )
                    conn.commit()
                    # Refresh actor row
                    cur = conn.execute("SELECT * FROM actors WHERE id = ?", (actor["id"],))
                    actor = cur.fetchone()
            except Exception:
                # If parsing fails, don't reset; proceed.
                pass

        attempt_number = int(actor["fail_count"]) + 1
        success = 1 if attempt_number >= 21 else 0  # allow on 21st try

        # Record the login attempt
        conn.execute(
            """
            INSERT INTO login_attempts (actor_id, ts_utc, username, password, success, attempt_number, repeater, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                actor["id"],
                utcnow_iso(),
                username,
                password,
                success,
                attempt_number,
                1 if repeater else 0,
                "threshold reached" if success else "invalid credentials",
            ),
        )
        conn.commit()

        if success:
            # Reset fail_count and mark last attempt
            conn.execute(
                "UPDATE actors SET fail_count = 0, last_attempt_utc = ? WHERE id = ?",
                (utcnow_iso(), actor["id"]),
            )
            conn.commit()
            session["honeypot_logged_in"] = True
            return redirect(url_for("welcome"))
        else:
            # Increment fail_count and mark last attempt
            conn.execute(
                "UPDATE actors SET fail_count = fail_count + 1, last_attempt_utc = ? WHERE id = ?",
                (utcnow_iso(), actor["id"]),
            )
            conn.commit()
            message = "Invalid username or password."

    return render_template("login.html", message=message)


@app.route("/welcome")
def welcome():
    if not session.get("honeypot_logged_in"):
        return redirect(url_for("login"))
    return render_template("success.html")


def _admin_authorized() -> bool:
    required = os.environ.get("HONEYPOT_ADMIN_TOKEN")
    if not required:
        return True
    provided = request.args.get("token") or request.headers.get("X-Admin-Token")
    return provided == required


@app.route("/admin")
def admin():
    if not _admin_authorized():
        return ("Forbidden", 403)

    conn = get_db()
    # Filters
    ip = (request.args.get("ip") or "").strip()
    ua = (request.args.get("ua") or "").strip()
    path_q = (request.args.get("path") or "").strip()
    qtype = (request.args.get("type") or "both").lower()
    try:
        hours = int(request.args.get("hours") or 24)
    except Exception:
        hours = 24
    try:
        limit = int(request.args.get("limit") or 100)
    except Exception:
        limit = 100
    limit = max(1, min(limit, 1000))

    since_iso = None
    if hours and hours > 0:
        since_iso = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    # Build requests query
    req_rows = []
    if qtype in ("both", "requests"):
        conds = ["1=1"]
        args = []
        if ip:
            conds.append("ip = ?")
            args.append(ip)
        if ua:
            conds.append("user_agent LIKE ?")
            args.append(f"%{ua}%")
        if path_q:
            conds.append("path LIKE ?")
            args.append(f"%{path_q}%")
        if since_iso:
            conds.append("ts_utc >= ?")
            args.append(since_iso)
        sql = (
            "SELECT id, ts_utc, ip, remote_port, local_port, method, scheme, host, path, query_string, user_agent, referrer "
            f"FROM requests WHERE {' AND '.join(conds)} ORDER BY id DESC LIMIT ?"
        )
        args.append(limit)
        cur = conn.execute(sql, tuple(args))
        req_rows = cur.fetchall()

    # Build login attempts query
    login_rows = []
    if qtype in ("both", "logins"):
        conds = ["1=1"]
        args = []
        if ip:
            conds.append("a.ip = ?")
            args.append(ip)
        if ua:
            conds.append("a.user_agent LIKE ?")
            args.append(f"%{ua}%")
        if since_iso:
            conds.append("la.ts_utc >= ?")
            args.append(since_iso)
        sql = (
            "SELECT la.id, la.ts_utc, a.ip, a.user_agent, la.username, la.password, la.success, la.attempt_number, la.repeater "
            "FROM login_attempts la JOIN actors a ON la.actor_id = a.id "
            f"WHERE {' AND '.join(conds)} ORDER BY la.id DESC LIMIT ?"
        )
        args.append(limit)
        cur = conn.execute(sql, tuple(args))
        login_rows = cur.fetchall()

    return render_template(
        "admin.html",
        req_rows=req_rows,
        login_rows=login_rows,
        ip=ip,
        ua=ua,
        path_q=path_q,
        qtype=qtype,
        hours=hours,
        limit=limit,
        token_provided=bool(request.args.get("token") or request.headers.get("X-Admin-Token")),
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
