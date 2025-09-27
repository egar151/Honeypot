# Honeypot / Sinkhole App

A minimal honeypot web application that:

- Logs every HTTP request (IP, remote/local ports, headers, method, path, body snippet).
- Provides a dummy login page and records each login attempt in plain text.
- Counts attempts per actor (identified by IP + User‑Agent) and, after 20 unsuccessful attempts, allows login on the 21st attempt and shows a confetti “break‑in” page.
- Resets the failed-attempt counter if there is no attempt for 15 minutes, while flagging that attempt as a repeater.
- Stores all data in a local SQLite database with safe, parameterized queries.

## Tech stack

- Python 3.9+
- Flask (minimal usage)
- SQLite (via Python standard library `sqlite3`)

## Run locally

1. Create a virtual environment and install deps:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install Flask
   ```

2. Start the app:

   ```bash
   python app.py
   ```

3. Visit:

   - http://localhost:8080/ (redirects to `/login`)

The app creates `honeypot.db` in the project root on first run.

## Installation

Prerequisites:

- Python 3.9 or newer (`python3 --version` to verify)
- macOS, Linux, or Windows (PowerShell commands equivalent)

Steps:

1) Clone/copy this folder to your machine.

2) Create a virtual environment and install dependencies:

   - macOS/Linux
     - `python3 -m venv .venv`
     - `source .venv/bin/activate`
     - `pip install -r requirements.txt`

   - Windows (PowerShell)
     - `py -3 -m venv .venv`
     - `.\.venv\Scripts\Activate.ps1`
     - `pip install -r requirements.txt`

3) Optionally set environment variables (see Security/Customization below).

4) Run:

   - `python app.py`

5) Open the app in your browser:

   - http://localhost:8080/

## Behavior details

- Request logging: Implemented in `@app.before_request`; logs IP (`X-Forwarded-For` aware), `REMOTE_PORT`, `SERVER_PORT`, method, scheme, host, path, query string, referrer, user agent, headers (as JSON), content type, and first 8KB of body.
- Actor identity: IP + User‑Agent. Each login attempt looks up/creates an actor; updates `last_seen_utc`.
- Attempt counting: `attempt_number = fail_count + 1` after applying 15‑minute idle reset. Attempts 1–20 always “invalid”. Attempt ≥ 21 is marked success and redirects to `/welcome`.
- 15‑minute reset: If idle ≥ 15 minutes since `last_attempt_utc`, resets `fail_count` to 0, increments `repeater_count`, and flags next attempt as repeater.
- Safety: All DB writes use parameterized queries. The UI does not echo user input back to pages. Jinja auto‑escaping is enabled by default.

## Read-only admin page

- URL: `/admin`
- Filters: IP, User-Agent (contains), Path (contains), last N hours (default 24), limit.
- Shows recent Requests and Login Attempts tables.
- Optional access token: set env var `HONEYPOT_ADMIN_TOKEN` and supply it via query `?token=...` or header `X-Admin-Token`.

## Usage

- Visiting any URL logs a request row automatically (method, path, ports, headers, body snippet).
- Go to `/login` and submit credentials; each attempt is recorded with `username`, `password`, `attempt_number`, and `repeater` flag.
- Attempts 1–20 always fail; attempt ≥ 21 succeeds and redirects to `/welcome` with confetti.
- Browse data at `/admin` (read-only). Use filters to narrow by IP, User-Agent, path, time window, and limit.

Inspecting the database directly (optional):

- `sqlite3 honeypot.db "SELECT COUNT(*) FROM requests;"`
- `sqlite3 honeypot.db "SELECT * FROM login_attempts ORDER BY id DESC LIMIT 5;"`

## Security and customization options

Environment variables:

- `PORT`: Server port (default `8080`). Example: `export PORT=9000`.
- `HONEYPOT_SECRET`: Flask session secret. Set this to a long, random, static value in production so sessions are stable across restarts. Example: `export HONEYPOT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')`.
- `HONEYPOT_ADMIN_TOKEN`: Optional token required to view `/admin`. Provide via query `?token=...` or header `X-Admin-Token`. If unset, `/admin` is open. Strongly recommended to set in any networked deployment.

Reverse proxy and IP handling:

- The app prefers the first IP from `X-Forwarded-For` when present. When deploying behind Nginx/HAProxy/Cloudflare, ensure your proxy is configured to set `X-Forwarded-For` and that only your proxy can reach the app.
- Example Nginx snippet:
  - `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`
  - `proxy_set_header X-Forwarded-Proto $scheme;`
  - `proxy_set_header Host $host;`

TLS/HTTPS:

- Terminate TLS at a reverse proxy (Nginx, Caddy, Traefik) and forward to the app on localhost. Do not expose Flask’s built-in server directly to the internet.

Body capture limits:

- The app stores only the first 8KB of the request body (`body_snippet`) to limit DB growth and avoid binary bloat. If you need to change this, edit `app.py` near `body_snippet = body_raw[:8192] ...` and adjust `8192` as desired.

Data retention and hygiene:

- SQLite file location: `honeypot.db` in project root.
- Consider periodic archival/rotation to avoid unbounded growth. Example cron job to vacuum weekly:
  - `sqlite3 /path/to/honeypot.db 'VACUUM;'`
- To export a CSV sample:
  - `sqlite3 -csv honeypot.db "SELECT * FROM requests ORDER BY id DESC LIMIT 100;" > requests_sample.csv`

Network exposure:

- By default, the app binds to `0.0.0.0` (all interfaces). For local-only testing, change to `127.0.0.1` in `app.py` or run behind a reverse proxy that restricts ingress.

Rate limiting and WAF:

- Not implemented in-app, but you can add it at the proxy:
  - Nginx `limit_req_zone` / `limit_req` to throttle abusive IPs.
  - Cloudflare/Load balancer rules to block/shape traffic.

Operational hardening:

- Run under a dedicated, unprivileged OS user.
- Keep `HONEYPOT_SECRET` and `HONEYPOT_ADMIN_TOKEN` outside source control (use env vars or a secret manager).
- Prefer running the app behind a reverse proxy with HTTPS and IP allowlists for `/admin`.

## Production deployment (example)

Gunicorn behind Nginx (Ubuntu-like setup):

1) Install gunicorn in the venv: `pip install gunicorn`
2) Start the app for testing: `gunicorn -w 2 -b 127.0.0.1:8080 app:app`
3) Nginx site example:
```
server {
    listen 80;
    server_name honeypot.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Optional: restrict admin
    location /admin {
        allow 10.0.0.0/8; # your network
        deny all;
        proxy_pass http://127.0.0.1:8080/admin;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Add TLS (Let’s Encrypt) via your preferred method (Certbot, Caddy, etc.).

Systemd unit (optional):

```
[Unit]
Description=Honeypot
After=network.target

[Service]
User=honeypot
WorkingDirectory=/opt/honeypot
Environment=PORT=8080
Environment=HONEYPOT_ADMIN_TOKEN=change-me
Environment=HONEYPOT_SECRET=change-me-long-random
ExecStart=/opt/honeypot/.venv/bin/gunicorn -w 2 -b 127.0.0.1:8080 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

- `Address already in use`: Change `PORT` or stop other processes bound to the same port.
- `sqlite3` not found: Install SQLite CLI or just use the app; Python includes the library already.
- Admin 403: Ensure you set `HONEYPOT_ADMIN_TOKEN` and passed `?token=...` or `X-Admin-Token` header.
- No IP in logs behind proxy: Confirm your reverse proxy sets `X-Forwarded-For` and only your proxy can reach the app.


## Database schema

Tables are created automatically on start:

- `requests(id, ts_utc, ip, remote_port, local_port, method, scheme, host, path, query_string, user_agent, referrer, headers_json, content_type, body_snippet)`
- `actors(id, ip, user_agent, fail_count, repeater_count, first_seen_utc, last_seen_utc, last_attempt_utc)`
- `login_attempts(id, actor_id, ts_utc, username, password, success, attempt_number, repeater, reason)`

## Notes

- This is a honeypot: never place behind real auth or connect it to production networks. If deploying behind a proxy/load balancer, ensure it forwards `X-Forwarded-For` correctly.
- If you want an admin view to browse logs, I can add a read-only web UI filtered by IP/time windows.
