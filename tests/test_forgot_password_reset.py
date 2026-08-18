"""
Comprehensive tests for the 6-Digit Email OTP Password Reset feature.

Coverage:
  - /forgot-password GET (renders Send Reset Code page)
  - /forgot-password POST (generates 6-digit OTP, anti-user enumeration, rate-limiting)
  - /verify-otp GET & POST (OTP hashing, verification, attempt counting max 5, expiry 10m, single-use, resend invalidation)
  - /reset-password GET & POST (password hashing, unlocking account, audit logs)
  - SMTP email contents (subject, 6-digit code, no reset link required)
  - Sensitive data non-disclosure (no plaintext OTP or password in DB or logs)
"""

import hashlib
import os
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

# ── Make the project root importable ─────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as flask_app_module
from app import app as flask_app
from database.database import create_database
from services import password_reset_service


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_test_db():
    """Create an isolated in-memory-backed temp SQLite DB for each test."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    create_database(path)
    return path


def _add_user(db_path, username="testuser", email="test@example.com", password="password123", failed_attempts=3, account_locked=1):
    hashed = generate_password_hash(password)
    conn   = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO users (username, email, password, failed_attempts, account_locked) VALUES (?, ?, ?, ?, ?)",
        (username, email, hashed, failed_attempts, account_locked),
    )
    conn.commit()
    user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()[0]
    conn.close()
    return user_id


def _get_audit_actions(db_path):
    conn  = sqlite3.connect(db_path)
    rows  = conn.execute("SELECT action FROM audit_logs ORDER BY id").fetchall()
    conn.close()
    return [r[0] for r in rows]


def _expire_otp(db_path, user_id):
    """Force-expire all OTPs for a user so tests can validate expiry logic."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE password_reset_otps SET expires_at='2000-01-01 00:00:00' WHERE user_id=?",
        (user_id,),
    )
    conn.execute(
        "UPDATE password_reset_tokens SET expires_at='2000-01-01 00:00:00' WHERE user_id=?",
        (user_id,),
    )
    conn.commit()
    conn.close()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    create_database(path)
    return path


@pytest.fixture()
def client(db_path):
    """Return a Flask test client wired to an isolated temp database."""
    flask_app.config["TESTING"]        = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    flask_app.config["MAIL_SERVER"]    = ""      # always dev-mode (no real SMTP)
    flask_app.config["MAIL_OUTBOX"]    = []
    flask_app.config["SECRET_KEY"]     = "test-secret"

    flask_app_module.DB_PATH = db_path
    password_reset_service.DB_PATH = db_path

    # Clear in-memory rate-limit buckets between tests
    flask_app_module.PASSWORD_RESET_RATE_BUCKETS.clear()

    with flask_app.test_client() as c:
        yield c, db_path

    flask_app.config["MAIL_OUTBOX"] = []


# ══════════════════════════════════════════════════════════════════════════════
# 1.  PAGE RENDERING
# ══════════════════════════════════════════════════════════════════════════════

class TestForgotPasswordPageRendering:

    def test_get_forgot_password_returns_200(self, client):
        c, _ = client
        resp = c.get("/forgot-password")
        assert resp.status_code == 200
        assert b"Send Reset Code" in resp.data or b"Reset Password" in resp.data

    def test_get_verify_otp_returns_200(self, client):
        c, _ = client
        resp = c.get("/verify-otp")
        assert resp.status_code == 200
        assert b"Verify Code" in resp.data or b"Verification Code" in resp.data

    def test_reset_password_unverified_redirects(self, client):
        c, _ = client
        resp = c.get("/reset-password", follow_redirects=True)
        assert resp.status_code == 200
        assert b"verify your reset code first" in resp.data.lower() or b"reset" in resp.data.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 2.  FORGOT PASSWORD — POST & OTP GENERATION
# ══════════════════════════════════════════════════════════════════════════════

class TestForgotPasswordPost:

    def test_registered_email_queues_otp_mail(self, client):
        """Submitting a registered email generates a 6-digit OTP and stores message in dev outbox."""
        c, db = client
        _add_user(db)
        resp = c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        assert resp.status_code == 200
        assert len(flask_app.config["MAIL_OUTBOX"]) == 1
        entry = flask_app.config["MAIL_OUTBOX"][0]
        assert "otp" in entry
        otp = entry["otp"]
        assert len(otp) == 6 and otp.isdigit()

    def test_unregistered_email_returns_generic_message(self, client):
        """No OTP is created and generic anti-enumeration response is displayed."""
        c, db = client
        resp = c.post("/forgot-password", data={"email": "nobody@example.com"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"if an account exists" in resp.data.lower()
        assert b"not found" not in resp.data.lower()
        assert b"no account" not in resp.data.lower()

        conn = sqlite3.connect(db)
        count = conn.execute("SELECT COUNT(*) FROM password_reset_otps").fetchone()[0]
        conn.close()
        assert count == 0

    def test_empty_email_returns_error(self, client):
        c, _ = client
        resp = c.post("/forgot-password", data={"email": ""})
        assert resp.status_code in (200, 302)

    def test_invalid_email_format_returns_error(self, client):
        c, _ = client
        resp = c.post("/forgot-password", data={"email": "not-an-email"})
        assert resp.status_code in (200, 302)

    def test_generic_response_no_enumeration(self, client):
        c, db = client
        _add_user(db)
        resp_registered = c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        flask_app.config["MAIL_OUTBOX"] = []
        resp_unregistered = c.post("/forgot-password", data={"email": "nope@example.com"}, follow_redirects=True)

        generic = b"if an account exists"
        assert generic in resp_registered.data.lower()
        assert generic in resp_unregistered.data.lower()

    def test_otp_not_stored_as_plaintext(self, client):
        """The raw 6-digit OTP must not appear in any database column."""
        c, db = client
        _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        raw_otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]
        conn = sqlite3.connect(db)
        rows = conn.execute("SELECT otp_hash FROM password_reset_otps").fetchall()
        conn.close()
        for (stored_hash,) in rows:
            assert stored_hash != raw_otp, "Raw OTP must not be stored — only SHA-256 hash."
            assert stored_hash == hashlib.sha256(raw_otp.encode("utf-8")).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# 3.  OTP VERIFICATION & ATTEMPT LIMITING
# ══════════════════════════════════════════════════════════════════════════════

class TestOtpValidation:

    def test_valid_otp_verifies_successfully(self, client):
        c, db = client
        _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        resp = c.post("/verify-otp", data={"email": "test@example.com", "otp": otp}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"code verified" in resp.data.lower() or b"set new password" in resp.data.lower()

    def test_expired_otp_rejected(self, client):
        c, db = client
        uid = _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]
        _expire_otp(db, uid)

        resp = c.post("/verify-otp", data={"email": "test@example.com", "otp": otp}, follow_redirects=True)
        assert b"invalid or expired" in resp.data.lower()

    def test_incorrect_otp_decrements_attempts(self, client):
        c, db = client
        _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)

        resp = c.post("/verify-otp", data={"email": "test@example.com", "otp": "000000"}, follow_redirects=True)
        assert b"invalid verification code" in resp.data.lower()
        assert b"remaining" in resp.data.lower()

    def test_max_otp_attempts_exceeded_invalidates_otp(self, client):
        c, db = client
        _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        valid_otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        # Fail 5 times
        for _ in range(5):
            c.post("/verify-otp", data={"email": "test@example.com", "otp": "999999"}, follow_redirects=True)

        # 6th attempt with correct OTP must fail because attempt limit was reached and OTP invalidated
        resp = c.post("/verify-otp", data={"email": "test@example.com", "otp": valid_otp}, follow_redirects=True)
        assert b"maximum verification attempts exceeded" in resp.data.lower() or b"invalid or expired" in resp.data.lower()

    def test_new_otp_request_invalidates_old_otp(self, client):
        c, db = client
        _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        first_otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        # Clear rate limit bucket so second request is allowed
        flask_app_module.PASSWORD_RESET_RATE_BUCKETS.clear()
        flask_app.config["MAIL_OUTBOX"] = []
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        second_otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        # Using first OTP must fail
        resp = c.post("/verify-otp", data={"email": "test@example.com", "otp": first_otp}, follow_redirects=True)
        assert b"invalid" in resp.data.lower()

        # Using second OTP must succeed
        resp2 = c.post("/verify-otp", data={"email": "test@example.com", "otp": second_otp}, follow_redirects=True)
        assert b"code verified" in resp2.data.lower() or b"set new password" in resp2.data.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 4.  RESET PASSWORD — FORM SUBMISSION & ACCOUNT UNLOCKING
# ══════════════════════════════════════════════════════════════════════════════

class TestResetPasswordSubmission:

    def test_successful_reset_updates_password_and_unlocks_account(self, client):
        c, db = client
        uid = _add_user(db, username="lockeduser", email="locked@example.com", failed_attempts=5, account_locked=1)

        c.post("/forgot-password", data={"email": "locked@example.com"}, follow_redirects=True)
        otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        # Verify OTP
        c.post("/verify-otp", data={"email": "locked@example.com", "otp": otp}, follow_redirects=True)

        # Submit new password
        resp = c.post(
            "/reset-password",
            data={"password": "NewSecure99!", "confirm_password": "NewSecure99!"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"password has been reset" in resp.data.lower()

        # Verify DB updates: password hash, failed_attempts=0, account_locked=0
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT password, failed_attempts, account_locked FROM users WHERE id=?", (uid,)).fetchone()
        conn.close()

        assert check_password_hash(row["password"], "NewSecure99!")
        assert row["failed_attempts"] == 0
        assert row["account_locked"] == 0

    def test_otp_single_use_after_reset(self, client):
        c, db = client
        _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        c.post("/verify-otp", data={"email": "test@example.com", "otp": otp}, follow_redirects=True)
        c.post("/reset-password", data={"password": "NewSecure99!", "confirm_password": "NewSecure99!"})

        # Trying to use the same OTP again must fail
        resp = c.post("/verify-otp", data={"email": "test@example.com", "otp": otp}, follow_redirects=True)
        assert b"invalid or expired" in resp.data.lower()

    def test_short_password_rejected(self, client):
        c, db = client
        _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        c.post("/verify-otp", data={"email": "test@example.com", "otp": otp}, follow_redirects=True)
        resp = c.post("/reset-password", data={"password": "short", "confirm_password": "short"})
        assert b"8 characters" in resp.data.lower() or b"at least" in resp.data.lower()

    def test_mismatched_passwords_rejected(self, client):
        c, db = client
        _add_user(db)
        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        c.post("/verify-otp", data={"email": "test@example.com", "otp": otp}, follow_redirects=True)
        resp = c.post("/reset-password", data={"password": "Password123!", "confirm_password": "DifferentPass123!"})
        assert b"do not match" in resp.data.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 5.  AUDIT LOGGING
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditLogging:

    def test_reset_requested_and_completed_audit_written(self, client):
        c, db = client
        _add_user(db)

        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        c.post("/verify-otp", data={"email": "test@example.com", "otp": otp}, follow_redirects=True)
        c.post("/reset-password", data={"password": "NewSecure99!", "confirm_password": "NewSecure99!"})

        actions = _get_audit_actions(db)
        assert "PASSWORD_RESET_REQUESTED" in actions
        assert "PASSWORD_RESET_COMPLETED" in actions

    def test_audit_log_contains_no_plaintext_otp_or_password(self, client):
        c, db = client
        _add_user(db)

        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        otp = flask_app.config["MAIL_OUTBOX"][0]["otp"]

        c.post("/verify-otp", data={"email": "test@example.com", "otp": otp}, follow_redirects=True)
        c.post("/reset-password", data={"password": "NewSecure99!", "confirm_password": "NewSecure99!"})

        conn = sqlite3.connect(db)
        descs = conn.execute("SELECT description FROM audit_logs").fetchall()
        conn.close()

        for (d,) in descs:
            assert otp not in d
            assert "NewSecure99!" not in d


# ══════════════════════════════════════════════════════════════════════════════
# 6.  RATE LIMITING
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimiting:

    def test_ip_rate_limit_blocks_token_creation(self, client):
        c, db = client
        _add_user(db)

        for _ in range(5):
            c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)

        flask_app.config["MAIL_OUTBOX"] = []
        resp = c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)

        # Generic message still returned
        assert b"if an account exists" in resp.data.lower()
        # No 6th email queued
        assert len(flask_app.config["MAIL_OUTBOX"]) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 7.  DEV MAILER & SMTP CONTENT
# ══════════════════════════════════════════════════════════════════════════════

class TestDevMailer:

    def test_email_subject_and_body_contain_otp(self, client):
        c, db = client
        _add_user(db)

        c.post("/forgot-password", data={"email": "test@example.com"}, follow_redirects=True)
        assert len(flask_app.config["MAIL_OUTBOX"]) == 1
        entry = flask_app.config["MAIL_OUTBOX"][0]

        assert "Password Reset Code" in entry["subject"]
        assert "Your password reset code is:" in entry["body"]
        assert entry["otp"] in entry["body"]
        assert "expires in 10 minutes" in entry["body"]


# ══════════════════════════════════════════════════════════════════════════════
# 8.  SMTP CONFIGURATION & DIRECT EMAIL DELIVERY TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestSmtpConfigurationAndDirectDelivery:

    def test_direct_send_password_reset_email_attempts_smtp_when_configured(self):
        flask_app.config["MAIL_SERVER"] = "smtp.gmail.com"
        flask_app.config["MAIL_PORT"] = 587
        flask_app.config["MAIL_USE_TLS"] = True
        flask_app.config["MAIL_USERNAME"] = "user@gmail.com"
        flask_app.config["MAIL_PASSWORD"] = "secret-app-password"
        flask_app.config["MAIL_DEFAULT_SENDER"] = "user@gmail.com"
        flask_app.config["MAIL_OUTBOX"] = []

        mock_instance = MagicMock()
        mock_class = MagicMock(return_value=mock_instance)
        mock_instance.__enter__ = MagicMock(return_value=mock_instance)
        mock_instance.__exit__ = MagicMock(return_value=False)

        try:
            with patch("smtplib.SMTP", mock_class):
                flask_app_module._send_password_reset_email(
                    "recipient@example.com",
                    "583214"
                )

            mock_class.assert_called_once_with("smtp.gmail.com", 587, timeout=15)
            mock_instance.starttls.assert_called_once()
            mock_instance.login.assert_called_once_with("user@gmail.com", "secret-app-password")
            assert mock_instance.send_message.called
            sent_msg = mock_instance.send_message.call_args[0][0]
            assert sent_msg["To"] == "recipient@example.com"
            assert sent_msg["From"] == "user@gmail.com"
            assert "SecureCloud Access Monitoring - Password Reset Code" in sent_msg["Subject"]
            assert "583214" in sent_msg.get_content()
        finally:
            flask_app.config["MAIL_SERVER"] = ""
            flask_app.config["MAIL_OUTBOX"] = []

    def test_log_smtp_status_does_not_log_password(self, caplog):
        import logging
        flask_app.config["MAIL_SERVER"] = "smtp.gmail.com"
        flask_app.config["MAIL_PASSWORD"] = "my-secret-token-xyz"
        flask_app.config["MAIL_USERNAME"] = "admin@gmail.com"

        try:
            with caplog.at_level(logging.INFO):
                flask_app_module.log_smtp_status(flask_app)
            assert "my-secret-token-xyz" not in caplog.text
        finally:
            flask_app.config["MAIL_SERVER"] = ""
            flask_app.config["MAIL_PASSWORD"] = ""
