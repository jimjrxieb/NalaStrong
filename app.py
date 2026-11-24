"""Local NalaStrong application. Start with python3 app.py serve."""
import argparse
import base64
import getpass
import hashlib
import hmac
import os
from contextlib import closing
from html import escape
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import time
from urllib.parse import parse_qs, quote
from wsgiref.simple_server import make_server

ROOT = Path(__file__).resolve().parent
ROLES = ("program", "approver", "finance", "reviewer")
SESSION_SECONDS = 3600
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60
TOTP_STEP_SECONDS = 30
NEXT = {
    "submitted": ("approver", "approved", "Approve"),
    "approved": ("finance", "paid", "Record payment"),
    "paid": ("reviewer", "reconciled", "Reconcile"),
}
PUBLIC = {
    "/": ("index.html", "text/html"),
    "/index.html": ("index.html", "text/html"),
    "/story.html": ("story.html", "text/html"),
    "/style.css": ("style.css", "text/css"),
    "/story-photos.js": ("story-photos.js", "text/javascript"),
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS staff (
    username TEXT PRIMARY KEY, role TEXT NOT NULL, salt BLOB NOT NULL, password BLOB NOT NULL,
    mfa_secret TEXT, mfa_last_step INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS login_failures (
    username TEXT NOT NULL, failed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_failures_by_user ON login_failures(username, failed_at);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES staff(username),
    expires INTEGER NOT NULL, csrf TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payouts (
    id INTEGER PRIMARY KEY, payee TEXT NOT NULL, purpose TEXT NOT NULL,
    cents INTEGER NOT NULL CHECK(cents > 0), requester TEXT NOT NULL REFERENCES staff(username),
    state TEXT NOT NULL, bank_reference TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, payout INTEGER NOT NULL REFERENCES payouts(id),
    actor TEXT NOT NULL REFERENCES staff(username), event TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit rows are append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit rows are append only'); END;
"""


def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db(db):
    db.executescript(SCHEMA)
    # Databases created before MFA existed lack these columns.
    columns = {row["name"] for row in db.execute("PRAGMA table_info(staff)")}
    if "mfa_secret" not in columns:
        db.execute("ALTER TABLE staff ADD COLUMN mfa_secret TEXT")
    if "mfa_last_step" not in columns:
        db.execute("ALTER TABLE staff ADD COLUMN mfa_last_step INTEGER NOT NULL DEFAULT 0")


def new_mfa_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp(secret, step):
    """RFC 6238 code. HMAC-SHA1 is the RFC default that authenticator apps require;
    HMAC-SHA1 is not affected by SHA-1 collision attacks."""
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(int.from_bytes(digest[offset:offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def verify_totp(secret, code, last_step, now):
    """Return the matched time step, or None. Rejects reuse of an already-used step."""
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int(now) // TOTP_STEP_SECONDS
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(totp(secret, step), code):
            return step
    return None


def session_cookie(value, max_age):
    return f"nala_session={value}; Path=/staff; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def money(cents):
    return f"${cents // 100:,}.{cents % 100:02d}"


def layout(title, content):
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{title} | NalaStrong</title>
<link rel="stylesheet" href="/style.css">
<body><header><a class="brand" href="/">NalaStrong</a></header>
<main><section><h1>{title}</h1>{content}</section></main></body></html>"""


def field(form, name):
    return form.get(name, [""])[0].strip()


def csrf_input(value):
    return f'<input type="hidden" name="csrf" value="{escape(value)}">'


def dashboard(db, user):
    csrf = csrf_input(user["csrf"])
    content = [
        f'<p>Signed in as {escape(user["username"])} · {escape(user["role"])}</p>',
        f'<form method="post" action="/staff/logout">{csrf}<button>Sign out</button></form>',
        '<p>Local development portal. Use synthetic records only.</p>',
    ]
    if user["role"] == "program":
        content.append(f"""<h2>Request assistance</h2><form method="post" action="/staff/payouts">{csrf}
<label>Payee <input name="payee" maxlength="120" required></label>
<label>Purpose or case ID <input name="purpose" maxlength="240" required></label>
<label>Amount in USD <input name="amount" inputmode="decimal" placeholder="68.00" required></label>
<button>Submit request</button></form>""")
    content.append("<h2>Assistance payouts</h2>")
    for payout in db.execute("SELECT * FROM payouts ORDER BY id DESC"):
        payout_id = payout["id"]
        content.append(f'<article><h3>Request {payout_id} · {money(payout["cents"])}</h3>'
                       f'<p>{escape(payout["payee"])} · {escape(payout["purpose"])}</p>'
                       f'<p>Status: {escape(payout["state"])}</p>')
        if payout["bank_reference"]:
            content.append(f'<p>Bank reference: {escape(payout["bank_reference"])}</p>')
        action = NEXT.get(payout["state"])
        if action and user["role"] == action[0] and user["username"] != payout["requester"]:
            reference = ('<label>Bank reference <input name="reference" maxlength="120" required></label>'
                         if action[1] == "paid" else "")
            content.append(f'<form method="post" action="/staff/payouts/{payout_id}">'
                           f'{csrf}{reference}<button>{action[2]}</button></form>')
        content.append("<details><summary>Audit history</summary><ol>")
        for row in db.execute("SELECT * FROM audit WHERE payout = ? ORDER BY id", (payout_id,)):
            content.append(f'<li>{escape(row["recorded_at"])} UTC · '
                           f'{escape(row["actor"])} · {escape(row["event"])}</li>')
        content.append("</ol></details></article>")
    return layout("Staff finance", "".join(content))


def create_app(path):
    def app(env, start):
        def respond(status, body="", *, location=None, cookie=None, kind="text/html", preview=False):
            headers = [
                ("Content-Type", kind if kind.startswith("image/") else kind + "; charset=utf-8"),
                ("X-Content-Type-Options", "nosniff"),
                ("Cache-Control", "no-store"),
                ("Content-Security-Policy", ("script-src 'self'; img-src 'self' blob:; " if preview else "") + "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
            ]
            if location:
                headers.append(("Location", location))
            if cookie:
                headers.append(("Set-Cookie", cookie))
            start(status, headers)
            return [body if isinstance(body, bytes) else body.encode()]

        def redirect(location, cookie=None):
            return respond("303 See Other", location=location, cookie=cookie)

        host = env.get("HTTP_HOST", "")
        if not re.fullmatch(r"(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?", host):
            return respond("400 Bad Request")
        route = env["PATH_INFO"]
        method = env["REQUEST_METHOD"]
        if method == "GET" and route in PUBLIC:
            filename, kind = PUBLIC[route]
            return respond("200 OK", (ROOT / "preview" / filename).read_text(), kind=kind, preview=filename == "index.html")
        photo_route = re.fullmatch(r"/family-photos/(nala-[1-9]\.jpg)", route)
        if method == "GET" and photo_route:
            # Local review only: family photos are gitignored and never part of a deployment.
            photo = ROOT / "preview" / "family-photos" / photo_route.group(1)
            if photo.is_file():
                return respond("200 OK", photo.read_bytes(), kind="image/jpeg")
            return respond("404 Not Found")
        payout_route = re.fullmatch(r"/staff/payouts/([1-9][0-9]{0,17})", route)
        if route not in {"/staff", "/staff/login", "/staff/logout", "/staff/payouts"} and not payout_route:
            return respond("404 Not Found")
        if method == "POST":
            # Restrict browser writes, including sign-in, to this local origin.
            if env.get("HTTP_ORIGIN") != "http://" + host:
                return respond("403 Forbidden")
            try:
                length = int(env.get("CONTENT_LENGTH") or 0)
                if not 0 < length <= 8192:
                    return respond("400 Bad Request")
                form = parse_qs(env["wsgi.input"].read(length).decode(), max_num_fields=10)
            except (ValueError, UnicodeError):
                return respond("400 Bad Request")
        cookies = SimpleCookie()
        try:
            cookies.load(env.get("HTTP_COOKIE", ""))
        except CookieError:
            return respond("400 Bad Request")
        session = cookies.get("nala_session")
        session_id = token_hash(session.value) if session else ""
        with closing(connect(path)) as db, db:
            if route == "/staff/login" and method == "POST":
                username = field(form, "username")
                password = form.get("password", [""])[0]
                failed = layout("Sign-in failed", '<p><a href="/staff">Try again</a></p>')
                if not 0 < len(username) <= 64 or len(password) > 256:
                    return respond("401 Unauthorized", failed)
                now = int(time.time())
                # Count failures per username (existing or not) so lockout does not reveal accounts.
                db.execute("DELETE FROM login_failures WHERE failed_at <= ?", (now - LOCKOUT_SECONDS,))
                failures = db.execute("SELECT COUNT(*) FROM login_failures WHERE username = ?",
                                      (username,)).fetchone()[0]
                if failures >= MAX_LOGIN_FAILURES:
                    return respond("429 Too Many Requests", layout(
                        "Sign-in locked", "<p>Too many failed attempts. Try again in 15 minutes.</p>"))
                account = db.execute("SELECT * FROM staff WHERE username = ?", (username,)).fetchone()
                digest = password_hash(password, account["salt"] if account else bytes(16))
                step = None
                if account and hmac.compare_digest(digest, account["password"]) and account["mfa_secret"]:
                    step = verify_totp(account["mfa_secret"], field(form, "code"), account["mfa_last_step"], now)
                if step is None:
                    db.execute("INSERT INTO login_failures VALUES (?, ?)", (username, now))
                    return respond("401 Unauthorized", failed)
                db.execute("UPDATE staff SET mfa_last_step = ? WHERE username = ?", (step, username))
                db.execute("DELETE FROM login_failures WHERE username = ?", (username,))
                token = secrets.token_urlsafe(32)
                db.execute("DELETE FROM sessions WHERE expires <= ? OR token = ?", (now, session_id))
                db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                           (token_hash(token), username, now + SESSION_SECONDS, secrets.token_urlsafe(32)))
                return redirect("/staff", session_cookie(token, SESSION_SECONDS))
            user = db.execute(
                """SELECT staff.username, staff.role, sessions.csrf FROM sessions JOIN staff USING(username)
                   WHERE token = ? AND expires > ?""", (session_id, int(time.time()))
            ).fetchone()
            if route == "/staff" and method == "GET":
                if user:
                    return respond("200 OK", dashboard(db, user))
                return respond("200 OK", layout("Staff sign-in", """
                    <form method="post" action="/staff/login">
                    <label>Username <input name="username" autocomplete="username" required></label>
                    <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
                    <label>Authenticator code <input name="code" inputmode="numeric" pattern="[0-9]{6}"
                        autocomplete="one-time-code" required></label>
                    <button>Sign in</button></form>"""))
            if method != "POST":
                return respond("405 Method Not Allowed")
            if not user or not hmac.compare_digest(field(form, "csrf").encode(), user["csrf"].encode()):
                return respond("403 Forbidden")
            if route == "/staff/logout":
                db.execute("DELETE FROM sessions WHERE token = ?", (session_id,))
                return redirect("/staff", session_cookie("", 0))
            if route == "/staff/payouts":
                if user["role"] != "program":
                    return respond("403 Forbidden")
                payee, purpose, amount = (field(form, name) for name in ("payee", "purpose", "amount"))
                if not (0 < len(payee) <= 120 and 0 < len(purpose) <= 240
                        and re.fullmatch(r"[0-9]{1,7}(?:\.[0-9]{1,2})?", amount)):
                    return respond("400 Bad Request")
                dollars, _, fraction = amount.partition(".")
                cents = int(dollars) * 100 + int(fraction.ljust(2, "0"))
                if cents == 0:
                    return respond("400 Bad Request")
                payout_id = db.execute(
                    "INSERT INTO payouts(payee, purpose, cents, requester, state) VALUES (?, ?, ?, ?, 'submitted')",
                    (payee, purpose, cents, user["username"]),
                ).lastrowid
                event = "submitted"
            elif payout_route:
                payout_id = int(payout_route[1])
                db.execute("BEGIN IMMEDIATE")
                payout = db.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
                if not payout:
                    return respond("404 Not Found")
                action = NEXT.get(payout["state"])
                if not action:
                    return respond("409 Conflict")
                if user["role"] != action[0] or user["username"] == payout["requester"]:
                    return respond("403 Forbidden")
                event = action[1]
                reference = payout["bank_reference"]
                if event == "paid":
                    reference = field(form, "reference")
                    if not 0 < len(reference) <= 120:
                        return respond("400 Bad Request")
                    if db.execute("SELECT 1 FROM payouts WHERE bank_reference = ?", (reference,)).fetchone():
                        return respond("409 Conflict")
                db.execute("UPDATE payouts SET state = ?, bank_reference = ? WHERE id = ?",
                           (event, reference, payout_id))
            else:
                return respond("405 Method Not Allowed")
            db.execute("INSERT INTO audit(payout, actor, event) VALUES (?, ?, ?)",
                       (payout_id, user["username"], event))
            return redirect("/staff")
    return app


def print_mfa_enrollment(username, secret):
    uri = f"otpauth://totp/NalaStrong:{quote(username)}?secret={secret}&issuer=NalaStrong"
    print(f"Add this account to an authenticator app, then clear the terminal.\n"
          f"Setup key: {secret}\nURI: {uri}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=ROOT / ".local" / "nalastrong.sqlite")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8000)
    staff = commands.add_parser("add-staff")
    staff.add_argument("username")
    staff.add_argument("role", choices=ROLES)
    enroll = commands.add_parser("enroll-mfa", help="Issue a new authenticator secret and end the user's sessions")
    enroll.add_argument("username")
    args = parser.parse_args()
    os.umask(0o077)
    args.database.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(args.database)) as db, db:
        init_db(db)
        if args.command == "enroll-mfa":
            if not db.execute("SELECT 1 FROM staff WHERE username = ?", (args.username,)).fetchone():
                parser.error("No staff account has that username.")
            secret = new_mfa_secret()
            db.execute("UPDATE staff SET mfa_secret = ?, mfa_last_step = 0 WHERE username = ?",
                       (secret, args.username))
            db.execute("DELETE FROM sessions WHERE username = ?", (args.username,))
            print_mfa_enrollment(args.username, secret)
            return
        if args.command == "add-staff":
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", args.username):
                parser.error("Use 1–64 letters, numbers, underscores or hyphens for usernames.")
            password = getpass.getpass("Local staff password: ")
            if not 12 <= len(password) <= 256 or password != getpass.getpass("Confirm password: "):
                parser.error("Use matching passwords between 12 and 256 characters.")
            salt = secrets.token_bytes(16)
            secret = new_mfa_secret()
            try:
                db.execute("INSERT INTO staff(username, role, salt, password, mfa_secret) VALUES (?, ?, ?, ?, ?)",
                           (args.username, args.role, salt, password_hash(password, salt), secret))
            except sqlite3.IntegrityError:
                parser.error("That username already exists.")
            print_mfa_enrollment(args.username, secret)
            return
    with make_server("127.0.0.1", args.port, create_app(args.database)) as server:
        print(f"NalaStrong is running at http://127.0.0.1:{args.port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
