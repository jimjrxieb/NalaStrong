"""BREAK suite for the NalaStrong staff finance portal.

Each test is a misuse case for the payout workflow (who can request, approve,
record, and reconcile) or for sign-in and session handling. Run from NALA/:

    python3 -m unittest discover -s tests -v

Uses only synthetic accounts in a throwaway SQLite file.
"""
import io
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing
from http.cookies import SimpleCookie
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402

HOST = "127.0.0.1:8000"
ORIGIN = "http://" + HOST
PASSWORD = "synthetic-password-1"


class Client:
    """Minimal WSGI client: one cookie jar, same-origin by default."""

    def __init__(self, wsgi):
        self.wsgi = wsgi
        self.cookie = ""

    def request(self, method, path, form=None, *, origin=ORIGIN, host=HOST):
        body = urlencode(form or {}).encode()
        env = {
            "REQUEST_METHOD": method, "PATH_INFO": path, "HTTP_HOST": host,
            "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body),
            "HTTP_COOKIE": self.cookie,
        }
        if origin is not None:
            env["HTTP_ORIGIN"] = origin
        captured = {}

        def start(status, headers):
            captured["status"] = int(status.split()[0])
            captured["headers"] = headers

        raw = b"".join(self.wsgi(env, start))
        captured["body"] = raw
        text = raw.decode(errors="replace")
        for name, value in captured["headers"]:
            if name == "Set-Cookie":
                captured["set_cookie"] = value
                jar = SimpleCookie()
                jar.load(value)
                morsel = jar["nala_session"]
                self.cookie = "" if morsel["max-age"] == "0" else f"nala_session={morsel.value}"
        return captured["status"], text, captured

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, form=None, **kw):
        return self.request("POST", path, form, **kw)


class PortalTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.sqlite"
        self.secrets = {}
        with closing(app.connect(self.db_path)) as db, db:
            app.init_db(db)
            for username, role in (("prog", "program"), ("appr", "approver"),
                                   ("fin", "finance"), ("rev", "reviewer"), ("prog2", "program")):
                salt = b"s" * 16
                secret = app.new_mfa_secret()
                self.secrets[username] = secret
                db.execute("INSERT INTO staff(username, role, salt, password, mfa_secret) VALUES (?, ?, ?, ?, ?)",
                           (username, role, salt, app.password_hash(PASSWORD, salt), secret))
        self.wsgi = app.create_app(self.db_path)

    def tearDown(self):
        self.tmp.cleanup()

    def code(self, username, offset=0):
        return app.totp(self.secrets[username], int(time.time()) // app.TOTP_STEP_SECONDS + offset)

    def login(self, username, *, code=None, password=PASSWORD):
        client = Client(self.wsgi)
        status, _, _ = client.post("/staff/login", {
            "username": username, "password": password,
            "code": self.code(username) if code is None else code})
        return client, status

    def signed_in(self, username):
        client, status = self.login(username)
        self.assertEqual(status, 303, f"{username} should sign in")
        return client

    def csrf(self, client):
        with closing(app.connect(self.db_path)) as db:
            row = db.execute("SELECT csrf FROM sessions JOIN staff USING(username) WHERE token = ?",
                             (app.token_hash(client.cookie.split("=", 1)[1]),)).fetchone()
        return row["csrf"]

    def act(self, client, path, **form):
        return client.post(path, {"csrf": self.csrf(client), **form})[0]

    def submit(self, client, amount="68.00"):
        status = self.act(client, "/staff/payouts", payee="Sample Vendor", purpose="CASE-0001", amount=amount)
        self.assertEqual(status, 303)
        with closing(app.connect(self.db_path)) as db:
            return db.execute("SELECT MAX(id) FROM payouts").fetchone()[0]

    def state(self, payout_id):
        with closing(app.connect(self.db_path)) as db:
            return db.execute("SELECT state FROM payouts WHERE id = ?", (payout_id,)).fetchone()["state"]


class WorkflowTests(PortalTestCase):
    def test_full_workflow_records_four_audit_events(self):
        payout = self.submit(self.signed_in("prog"))
        self.assertEqual(self.act(self.signed_in("appr"), f"/staff/payouts/{payout}"), 303)
        self.assertEqual(self.act(self.signed_in("fin"), f"/staff/payouts/{payout}", reference="BANK-1"), 303)
        self.assertEqual(self.act(self.signed_in("rev"), f"/staff/payouts/{payout}"), 303)
        self.assertEqual(self.state(payout), "reconciled")
        with closing(app.connect(self.db_path)) as db:
            events = [(r["actor"], r["event"]) for r in
                      db.execute("SELECT actor, event FROM audit WHERE payout = ? ORDER BY id", (payout,))]
        self.assertEqual(events, [("prog", "submitted"), ("appr", "approved"),
                                  ("fin", "paid"), ("rev", "reconciled")])

    def test_only_program_role_can_request(self):
        for username in ("appr", "fin", "rev"):
            status = self.act(self.signed_in(username), "/staff/payouts",
                              payee="X", purpose="CASE-0002", amount="10.00")
            self.assertEqual(status, 403, username)

    def test_roles_cannot_skip_approval_steps(self):
        payout = self.submit(self.signed_in("prog"))
        for username in ("fin", "rev", "prog2"):
            self.assertEqual(self.act(self.signed_in(username), f"/staff/payouts/{payout}", reference="BANK-2"),
                             403, username)
        self.assertEqual(self.state(payout), "submitted")

    def test_requester_cannot_advance_own_request(self):
        client = self.signed_in("prog")
        payout = self.submit(client)
        self.assertEqual(self.act(client, f"/staff/payouts/{payout}"), 403)
        self.assertEqual(self.state(payout), "submitted")

    def test_duplicate_bank_reference_is_rejected(self):
        prog, appr, fin = (self.signed_in(u) for u in ("prog", "appr", "fin"))
        first, second = self.submit(prog), self.submit(prog)
        for payout in (first, second):
            self.assertEqual(self.act(appr, f"/staff/payouts/{payout}"), 303)
        self.assertEqual(self.act(fin, f"/staff/payouts/{first}", reference="BANK-DUP"), 303)
        self.assertEqual(self.act(fin, f"/staff/payouts/{second}", reference="BANK-DUP"), 409)
        self.assertEqual(self.state(second), "approved")

    def test_reconciled_payout_cannot_advance_further(self):
        payout = self.submit(self.signed_in("prog"))
        self.act(self.signed_in("appr"), f"/staff/payouts/{payout}")
        self.act(self.signed_in("fin"), f"/staff/payouts/{payout}", reference="BANK-3")
        reviewer = self.signed_in("rev")  # one sign-in: a second would replay the same TOTP step
        self.act(reviewer, f"/staff/payouts/{payout}")
        self.assertEqual(self.act(reviewer, f"/staff/payouts/{payout}"), 409)

    def test_invalid_amounts_are_rejected(self):
        client = self.signed_in("prog")
        for amount in ("0", "0.00", "-5", "1.234", "abc", "100000000", ""):
            status = self.act(client, "/staff/payouts", payee="X", purpose="CASE-0003", amount=amount)
            self.assertEqual(status, 400, amount)

    def test_audit_rows_are_append_only(self):
        self.submit(self.signed_in("prog"))
        with closing(sqlite3.connect(self.db_path)) as db:
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute("UPDATE audit SET actor = 'someone-else'")
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute("DELETE FROM audit")


class RequestBoundaryTests(PortalTestCase):
    def test_unauthenticated_write_is_forbidden(self):
        status, _, _ = Client(self.wsgi).post("/staff/payouts", {"payee": "X", "purpose": "Y", "amount": "1"})
        self.assertEqual(status, 403)

    def test_missing_or_wrong_csrf_is_forbidden(self):
        client = self.signed_in("prog")
        form = {"payee": "X", "purpose": "Y", "amount": "1.00"}
        self.assertEqual(client.post("/staff/payouts", form)[0], 403)
        self.assertEqual(client.post("/staff/payouts", {**form, "csrf": "wrong"})[0], 403)

    def test_cross_origin_post_is_forbidden(self):
        client = self.signed_in("prog")
        form = {"payee": "X", "purpose": "Y", "amount": "1.00", "csrf": self.csrf(client)}
        self.assertEqual(client.post("/staff/payouts", form, origin="http://evil.example")[0], 403)
        self.assertEqual(client.post("/staff/payouts", form, origin=None)[0], 403)

    def test_unexpected_host_header_is_rejected(self):
        self.assertEqual(Client(self.wsgi).get("/", host="evil.example")[0], 400)

    def test_security_headers_present(self):
        _, _, meta = Client(self.wsgi).get("/staff")
        headers = dict(meta["headers"])
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Cache-Control"], "no-store")


class SessionTests(PortalTestCase):
    def test_session_cookie_flags(self):
        client = Client(self.wsgi)
        _, _, meta = client.post("/staff/login", {"username": "prog", "password": PASSWORD,
                                                  "code": self.code("prog")})
        cookie = meta["set_cookie"]
        for flag in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/staff"):
            self.assertIn(flag, cookie)

    def test_session_tokens_are_stored_hashed(self):
        client = self.signed_in("prog")
        raw = client.cookie.split("=", 1)[1]
        with closing(app.connect(self.db_path)) as db:
            tokens = [r["token"] for r in db.execute("SELECT token FROM sessions")]
        self.assertNotIn(raw, tokens)
        self.assertIn(app.token_hash(raw), tokens)

    def test_expired_session_is_rejected(self):
        client = self.signed_in("prog")
        with closing(app.connect(self.db_path)) as db, db:
            db.execute("UPDATE sessions SET expires = ?", (int(time.time()) - 1,))
        status, text, _ = client.get("/staff")
        self.assertIn("Staff sign-in", text)
        self.assertEqual(self.act_raw(client), 403)

    def test_logout_invalidates_session_server_side(self):
        client = self.signed_in("prog")
        stolen = client.cookie
        self.assertEqual(self.act(client, "/staff/logout"), 303)
        replay = Client(self.wsgi)
        replay.cookie = stolen
        self.assertIn("Staff sign-in", replay.get("/staff")[1])

    def act_raw(self, client):
        return client.post("/staff/payouts", {"payee": "X", "purpose": "Y", "amount": "1.00",
                                              "csrf": "anything"})[0]


class SignInTests(PortalTestCase):
    def test_wrong_password_is_rejected(self):
        self.assertEqual(self.login("prog", password="not-the-password")[1], 401)

    def test_unknown_user_is_rejected_the_same_way(self):
        self.assertEqual(self.login("nobody", code="000000")[1], 401)

    def test_correct_password_without_valid_code_is_rejected(self):
        self.assertEqual(self.login("prog", code="")[1], 401)
        wrong = "000000" if self.code("prog") != "000000" else "111111"
        self.assertEqual(self.login("prog", code=wrong)[1], 401)

    def test_codes_outside_the_window_are_rejected(self):
        self.assertEqual(self.login("prog", code=self.code("prog", offset=-3))[1], 401)

    def test_authenticator_code_cannot_be_replayed(self):
        code = self.code("prog")
        self.assertEqual(self.login("prog", code=code)[1], 303)
        self.assertEqual(self.login("prog", code=code)[1], 401)

    def test_account_without_mfa_cannot_sign_in(self):
        with closing(app.connect(self.db_path)) as db, db:
            db.execute("UPDATE staff SET mfa_secret = NULL WHERE username = 'prog'")
        self.assertEqual(self.login("prog", code="123456")[1], 401)

    def test_lockout_after_repeated_failures_even_with_correct_credentials(self):
        for _ in range(app.MAX_LOGIN_FAILURES):
            self.assertEqual(self.login("prog", password="wrong-password")[1], 401)
        self.assertEqual(self.login("prog")[1], 429)

    def test_lockout_applies_to_unknown_usernames(self):
        for _ in range(app.MAX_LOGIN_FAILURES):
            self.login("ghost", code="000000")
        self.assertEqual(self.login("ghost", code="000000")[1], 429)

    def test_lockout_expires(self):
        old = int(time.time()) - app.LOCKOUT_SECONDS - 1
        with closing(app.connect(self.db_path)) as db, db:
            db.executemany("INSERT INTO login_failures VALUES ('prog', ?)",
                           [(old,)] * app.MAX_LOGIN_FAILURES)
        self.assertEqual(self.login("prog")[1], 303)

    def test_successful_sign_in_clears_failure_count(self):
        for _ in range(app.MAX_LOGIN_FAILURES - 1):
            self.login("prog", password="wrong-password")
        self.assertEqual(self.login("prog")[1], 303)
        with closing(app.connect(self.db_path)) as db:
            count = db.execute("SELECT COUNT(*) FROM login_failures WHERE username = 'prog'").fetchone()[0]
        self.assertEqual(count, 0)


class TotpTests(unittest.TestCase):
    def test_rfc6238_sha1_vector(self):
        # RFC 6238 Appendix B, T = 59 seconds, 8-digit 94287082 -> last 6 digits 287082.
        secret = __import__("base64").b32encode(b"12345678901234567890").decode()
        self.assertEqual(app.totp(secret, 59 // 30), "287082")


class MigrationTests(unittest.TestCase):
    def test_pre_mfa_database_is_migrated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.sqlite"
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("CREATE TABLE staff (username TEXT PRIMARY KEY, role TEXT NOT NULL, "
                           "salt BLOB NOT NULL, password BLOB NOT NULL)")
                db.execute("INSERT INTO staff VALUES ('legacy', 'program', x'00', x'00')")
            with closing(app.connect(path)) as db, db:
                app.init_db(db)
                row = db.execute("SELECT mfa_secret, mfa_last_step FROM staff").fetchone()
            self.assertIsNone(row["mfa_secret"])
            self.assertEqual(row["mfa_last_step"], 0)


# Synthetic stand-in bytes: real family photos are gitignored and never reach CI.
FAKE_JPEG = b"\xff\xd8\xff\xe0synthetic-test-photo\xff\xd9"


class FamilyPhotoRouteTests(unittest.TestCase):
    """The local-review photo route must serve only nala-[1-9].jpg from preview/family-photos/."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        photos = root / "preview" / "family-photos"
        photos.mkdir(parents=True)
        (photos / "nala-1.jpg").write_bytes(FAKE_JPEG)
        (photos / "nala-1.jpg.bak").write_bytes(b"backup")
        (photos / "notes.txt").write_text("private")
        (root / "preview" / "secret.txt").write_text("private")
        (root / "app.py").write_text("private")
        (photos / "nala-3.jpg").mkdir()  # a directory with a photo name is not a photo
        patcher = mock.patch.object(app, "ROOT", root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.client = Client(app.create_app(root / "test.sqlite"))

    def test_existing_photo_is_served_as_jpeg(self):
        status, _, meta = self.client.get("/family-photos/nala-1.jpg")
        self.assertEqual(status, 200)
        self.assertEqual(meta["body"], FAKE_JPEG)
        headers = dict(meta["headers"])
        self.assertEqual(headers["Content-Type"], "image/jpeg")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertTrue(headers["Content-Security-Policy"].startswith("default-src 'none'"))

    def test_missing_photo_is_not_found(self):
        self.assertEqual(self.client.get("/family-photos/nala-2.jpg")[0], 404)

    def test_directory_named_like_a_photo_is_not_found(self):
        self.assertEqual(self.client.get("/family-photos/nala-3.jpg")[0], 404)

    def test_names_outside_the_allowed_pattern_are_not_found(self):
        for path in ("/family-photos/nala-0.jpg", "/family-photos/nala-10.jpg",
                     "/family-photos/nala-1.jpg.bak", "/family-photos/NALA-1.JPG",
                     "/family-photos/nala-1.jpeg", "/family-photos/nala-1.png",
                     "/family-photos/nala-1.jpg/", "/family-photos/notes.txt",
                     "/family-photos/", "/family-photos", "/preview/family-photos/nala-1.jpg"):
            with self.subTest(path=path):
                status, _, meta = self.client.get(path)
                self.assertEqual(status, 404)
                self.assertNotIn(b"private", meta["body"])

    def test_path_traversal_is_not_found(self):
        for path in ("/family-photos/../secret.txt", "/family-photos/../../app.py",
                     "/family-photos/..%2fsecret.txt", "/family-photos/%2e%2e/secret.txt",
                     "/family-photos/nala-1.jpg/../../secret.txt", "/family-photos//nala-1.jpg",
                     "/family-photos/nala-1.jpg\x00.txt", "/family-photos/..\\secret.txt"):
            with self.subTest(path=path):
                status, _, meta = self.client.get(path)
                self.assertEqual(status, 404)
                self.assertNotIn(b"private", meta["body"])

    def test_only_get_is_served(self):
        for method in ("POST", "PUT", "DELETE", "HEAD"):
            with self.subTest(method=method):
                status, _, meta = self.client.request(method, "/family-photos/nala-1.jpg")
                self.assertNotEqual(status, 200)
                self.assertNotEqual(meta["body"], FAKE_JPEG)

    def test_unexpected_host_cannot_fetch_photos(self):
        self.assertEqual(self.client.get("/family-photos/nala-1.jpg", host="evil.example")[0], 400)
        self.assertEqual(self.client.get("/family-photos/nala-1.jpg", host="nalastrong.org")[0], 400)

    def test_family_photo_folder_is_gitignored(self):
        ignore = (Path(__file__).resolve().parent.parent / ".gitignore").read_text().splitlines()
        self.assertIn("/preview/family-photos/", ignore)


class PreviewPolicyTests(unittest.TestCase):
    """Only the homepage gets the script and image allowances that the photo preview needs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db_path = Path(self.tmp.name) / "test.sqlite"
        with closing(app.connect(db_path)) as db, db:
            app.init_db(db)
        self.client = Client(app.create_app(db_path))

    def policy(self, path):
        status, _, meta = self.client.get(path)
        self.assertEqual(status, 200, path)
        return dict(meta["headers"])["Content-Security-Policy"]

    def test_homepage_allows_same_origin_script_and_blob_images_only(self):
        for path in ("/", "/index.html"):
            with self.subTest(path=path):
                policy = self.policy(path)
                self.assertIn("script-src 'self';", policy)
                self.assertIn("img-src 'self' blob:;", policy)
                self.assertIn("default-src 'none'", policy)
                self.assertIn("frame-ancestors 'none'", policy)
                self.assertNotIn("unsafe-inline", policy)
                self.assertNotIn("unsafe-eval", policy)
                self.assertNotIn("*", policy)

    def test_other_pages_keep_the_strict_policy(self):
        for path in ("/story.html", "/style.css", "/story-photos.js", "/staff"):
            with self.subTest(path=path):
                policy = self.policy(path)
                self.assertNotIn("script-src", policy)
                self.assertNotIn("img-src", policy)
                self.assertTrue(policy.startswith("default-src 'none'"))

    def test_photo_script_is_served_as_javascript(self):
        status, text, meta = self.client.get("/story-photos.js")
        self.assertEqual(status, 200)
        self.assertEqual(dict(meta["headers"])["Content-Type"], "text/javascript; charset=utf-8")
        self.assertIn("loadFamilyPhotos", text)

    def test_photo_script_only_runs_on_local_hosts(self):
        script = (Path(__file__).resolve().parent.parent / "preview" / "story-photos.js").read_text()
        self.assertIn('["localhost", "127.0.0.1", "[::1]"].includes(location.hostname)', script)


if __name__ == "__main__":
    unittest.main()
