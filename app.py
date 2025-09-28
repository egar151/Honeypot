import json
import os
import sqlite3
import random
import secrets
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
            body_snippet TEXT,
            first_visit_ever INTEGER NOT NULL DEFAULT 0,
            first_visit_today INTEGER NOT NULL DEFAULT 0
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
    # Backfill/migrate: ensure new columns exist
    def ensure_column(table: str, name: str, ddl: str):
        cur.execute(f"PRAGMA table_info({table});")
        cols = [r[1] for r in cur.fetchall()]
        if name not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl};")
            conn.commit()

    ensure_column("requests", "first_visit_ever", "INTEGER NOT NULL DEFAULT 0")
    ensure_column("requests", "first_visit_today", "INTEGER NOT NULL DEFAULT 0")

    # Whitelist for admin access via URL knocking
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            session_id TEXT,
            created_utc TEXT NOT NULL,
            expires_utc TEXT
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

    # Determine first-visit signals (by ip + user agent)
    ip_val = client_ip()
    ua_val = request.headers.get("User-Agent", "")
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(1) FROM requests WHERE ip = ? AND user_agent = ?",
        (ip_val, ua_val),
    )
    total_for_actor = int(cur.fetchone()[0])
    first_visit_ever = 1 if total_for_actor == 0 else 0

    # First visit today (UTC)
    now_dt = datetime.now(timezone.utc)
    start_of_day = datetime(now_dt.year, now_dt.month, now_dt.day, tzinfo=timezone.utc)
    cur.execute(
        "SELECT COUNT(1) FROM requests WHERE ip = ? AND user_agent = ? AND ts_utc >= ?",
        (ip_val, ua_val, start_of_day.isoformat()),
    )
    total_today = int(cur.fetchone()[0])
    first_visit_today = 1 if total_today == 0 else 0

    conn.execute(
        """
        INSERT INTO requests (
            ts_utc, ip, remote_port, local_port, method, scheme, host, path, query_string,
            user_agent, referrer, headers_json, content_type, body_snippet, first_visit_ever, first_visit_today
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            utcnow_iso(),
            ip_val,
            remote_port,
            local_port,
            request.method,
            request.scheme,
            request.host,
            request.path,
            request.query_string.decode("utf-8", errors="replace") if isinstance(request.query_string, (bytes, bytearray)) else str(request.query_string),
            ua_val,
            request.referrer or "",
            headers_json,
            request.headers.get("Content-Type", ""),
            body_snippet,
            first_visit_ever,
            first_visit_today,
        ),
    )
    conn.commit()


app = Flask(__name__)
app.secret_key = os.environ.get("HONEYPOT_SECRET", os.urandom(24))

# Knock configuration
def _knock_sequence() -> list[str]:
    raw = os.environ.get("KNOCK_SEQUENCE", "/knock/one,/knock/two,/knock/three")
    seq = [s.strip() for s in raw.split(",") if s.strip()]
    # Normalize to paths starting with '/'
    seq = [p if p.startswith("/") else f"/{p}" for p in seq]
    return seq

def _knock_window_seconds() -> int:
    try:
        return int(os.environ.get("KNOCK_WINDOW_SEC", "60"))
    except Exception:
        return 60

def _whitelist_hours() -> int:
    try:
        return int(os.environ.get("KNOCK_WHITELIST_HOURS", "12"))
    except Exception:
        return 12


@app.before_request
def _before_request_log():
    # Exclude style.css from request logging as requested
    if request.path == "/static/style.css":
        return
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
    return render_template("index.html")


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
    # If whitelisted by session
    if session.get("admin_whitelisted"):
        return True

    # If whitelisted by IP and not expired
    try:
        conn = get_db()
        now_iso = utcnow_iso()
        cur = conn.execute(
            "SELECT 1 FROM whitelist WHERE (ip = ? OR (session_id IS NOT NULL AND session_id = ?)) AND (expires_utc IS NULL OR expires_utc > ?) LIMIT 1",
            (client_ip(), session.get("sid", ""), now_iso),
        )
        if cur.fetchone():
            return True
    except Exception:
        pass

    # Fallback to token auth if configured
    required = os.environ.get("HONEYPOT_ADMIN_TOKEN")
    if not required:
        return False
    provided = request.args.get("token") or request.headers.get("X-Admin-Token")
    return provided == required


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not _admin_authorized():
        return ("Forbidden", 403)

    conn = get_db()
    purge_ok = False
    purge_error = None
    wl_removed = None
    wl_error = None

    # Handle purge action
    if request.method == "POST" and (request.form.get("action") == "purge"):
        supplied = (request.form.get("confirm") or "").strip()
        today_pwd = datetime.now().strftime("%m%d%Y")
        if supplied == today_pwd:
            try:
                # Purge logs and attempts. Keep whitelist intact.
                conn.execute("DELETE FROM requests;")
                conn.execute("DELETE FROM login_attempts;")
                conn.execute("DELETE FROM actors;")
                conn.commit()
                purge_ok = True
            except Exception as e:
                purge_error = f"Failed to purge: {e}"
        else:
            purge_error = "Invalid password."

    # Handle whitelist removal
    if request.method == "POST" and (request.form.get("action") == "del_whitelist"):
        try:
            wid = int(request.form.get("id") or 0)
        except Exception:
            wid = 0
        if wid > 0:
            try:
                cur = conn.execute("DELETE FROM whitelist WHERE id = ?", (wid,))
                conn.commit()
                wl_removed = wid if cur.rowcount else None
                if wl_removed is None:
                    wl_error = "Record not found."
            except Exception as e:
                wl_error = f"Failed to remove: {e}"
        else:
            wl_error = "Invalid id."
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
            "SELECT id, ts_utc, ip, remote_port, local_port, method, scheme, host, path, query_string, user_agent, referrer, first_visit_ever, first_visit_today "
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

    # Whitelist entries (authorized devices/sessions)
    try:
        now_iso = utcnow_iso()
        cur = conn.execute(
            "SELECT id, ip, session_id, created_utc, expires_utc, CASE WHEN (expires_utc IS NULL OR expires_utc > ?) THEN 1 ELSE 0 END AS active FROM whitelist ORDER BY id DESC LIMIT ?",
            (now_iso, limit),
        )
        whitelist_rows = cur.fetchall()
    except Exception:
        whitelist_rows = []

    return render_template(
        "admin.html",
        req_rows=req_rows,
        login_rows=login_rows,
        whitelist_rows=whitelist_rows,
        ip=ip,
        ua=ua,
        path_q=path_q,
        qtype=qtype,
        hours=hours,
        limit=limit,
        token_provided=bool(request.args.get("token") or request.headers.get("X-Admin-Token")),
        purge_ok=purge_ok,
        purge_error=purge_error,
        wl_removed=wl_removed,
        wl_error=wl_error,
    )


def _ensure_session_id():
    if not session.get("sid"):
        session["sid"] = secrets.token_hex(16)


def _knock_progress_reset():
    session.pop("knock_idx", None)
    session.pop("knock_started", None)


def _handle_knock_sequence(path: str):
    # Return True if we should short-circuit (e.g., after completing knocks) or False to continue
    seq = _knock_sequence()
    if not seq:
        return False

    _ensure_session_id()
    now = datetime.now(timezone.utc)
    idx = int(session.get("knock_idx", 0))
    started_iso = session.get("knock_started")
    started = None
    if started_iso:
        try:
            started = datetime.fromisoformat(started_iso)
        except Exception:
            started = None

    # If window expired, reset
    if started and (now - started).total_seconds() > _knock_window_seconds():
        _knock_progress_reset()
        idx = 0
        started = None

    expected = seq[idx] if idx < len(seq) else None
    if expected and path == expected:
        # Progress sequence
        if idx == 0:
            session["knock_started"] = now.isoformat()
        session["knock_idx"] = idx + 1
        if idx + 1 >= len(seq):
            # Completed within window — whitelist
            expires = now + timedelta(hours=_whitelist_hours())
            try:
                conn = get_db()
                conn.execute(
                    "INSERT INTO whitelist (ip, session_id, created_utc, expires_utc) VALUES (?, ?, ?, ?)",
                    (client_ip(), session.get("sid"), now.isoformat(), expires.isoformat()),
                )
                conn.commit()
            except Exception:
                pass
            session["admin_whitelisted"] = True
            _knock_progress_reset()
        # Respond minimally to knocks to avoid attention
        return True
    return False


def _random_file_response(path: str):
    # Generate realistic-looking text content depending on extension or random template
    name = os.path.basename(path.strip("/")) or "index"
    exts = [".log", ".txt", ".csv", ".conf", ".ini", ".json"]
    ext = os.path.splitext(name)[1]
    if not ext:
        ext = random.choice(exts)
        name = name + ext

    now = datetime.now(timezone.utc)
    host = request.host or "localhost"
    ip = client_ip()

    def gen_log():
        lines = []
        for i in range(random.randint(30, 120)):
            ts = (now - timedelta(seconds=random.randint(0, 3600))).strftime("%Y-%m-%d %H:%M:%S")
            lvl = random.choice(["INFO", "WARN", "ERROR", "DEBUG"])
            mod = random.choice(["auth", "db", "api", "nginx", "system"]) 
            msg = random.choice([
                "accepted connection",
                "authentication failed for user",
                "executed query",
                "cache miss",
                "request completed",
                "permission denied",
                "rotating keys",
            ])
            lines.append(f"{ts} {lvl} {mod}: {msg}")
        return "\n".join(lines) + "\n"

    def gen_csv():
        headers = ["id", "name", "email", "role", "last_login"]
        rows = [",".join(headers)]
        for i in range(1, random.randint(20, 80)):
            rows.append(f"{i},User {i},user{i}@{host.split(':')[0]},user,{(now - timedelta(days=random.randint(0,90))).date()}")
        return "\n".join(rows) + "\n"

    def gen_conf():
        blocks = [
            "[server]\nport=8080\nhost=0.0.0.0\n",
            f"[database]\nengine=sqlite\npath={DB_PATH}\n",
            f"[auth]\nprovider=internal\nrate_limit={random.randint(5,20)}/min\n",
        ]
        return "\n".join(blocks)

    def gen_json():
        sample = {
            "service": "api",
            "version": "v1",
            "host": host,
            "timestamp": now.isoformat(),
            "status": "ok",
            "client": {"ip": ip, "ua": request.headers.get("User-Agent", "")},
        }
        return json.dumps(sample, indent=2) + "\n"

    content = ""
    if ext == ".csv":
        content = gen_csv()
        mime = "text/csv"
    elif ext == ".json":
        content = gen_json()
        mime = "application/json"
    elif ext in (".conf", ".ini"):
        content = gen_conf()
        mime = "text/plain"
    else:
        content = gen_log()
        mime = "text/plain"

    from flask import Response
    resp = Response(content, mimetype=mime)
    resp.headers["Content-Disposition"] = f"inline; filename={name}"
    return resp


@app.route("/<path:anypath>")
def catch_all(anypath: str):
    # Normalize path with leading '/'
    path = "/" + anypath
    # First: process knock sequence
    if _handle_knock_sequence(path):
        # Return generic not found to stay inconspicuous
        return ("Not Found", 404)

    # Known routes should not be shadowed (Flask routing handles this already),
    # but for safety, avoid mimicking our main endpoints.
    if path in ("/login", "/welcome", "/admin"):
        return redirect(path)
    # Serve a realistic random text file for any other path
    return _random_file_response(path)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
