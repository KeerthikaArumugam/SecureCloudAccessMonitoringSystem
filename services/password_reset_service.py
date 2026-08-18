"""Secure, database-backed single-use 6-digit password reset OTP service."""
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database.db")

RESET_OTP_TTL_MINUTES = 10
RESET_TOKEN_TTL_MINUTES = 10
MAX_OTP_ATTEMPTS = 5


def _now():
    return datetime.now(timezone.utc)


def _stamp(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def otp_digest(otp_str: str) -> str:
    """Return SHA-256 hex digest of the 6-digit numeric OTP."""
    return hashlib.sha256((otp_str or "").strip().encode("utf-8")).hexdigest()


def token_digest(token):
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def create_reset_otp(user_id: int) -> str:
    """Generate a cryptographically secure 6-digit numeric OTP, invalidate previous unused OTPs, and return raw OTP."""
    otp = f"{secrets.randbelow(900000) + 100000}"
    now = _now()
    expires_at = now + timedelta(minutes=RESET_OTP_TTL_MINUTES)

    conn = sqlite3.connect(DB_PATH)
    try:
        # Requirement 6: A new OTP request must invalidate previous unused OTPs for that user
        conn.execute(
            "UPDATE password_reset_otps SET used_at=? WHERE user_id=? AND used_at IS NULL",
            (_stamp(now), user_id)
        )
        # Also invalidate old tokens if any exist
        conn.execute(
            "UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL",
            (_stamp(now), user_id)
        )
        # Requirement 3: Do NOT store the plaintext OTP in the database. Store only a secure hash.
        conn.execute(
            "INSERT INTO password_reset_otps (user_id, otp_hash, expires_at, attempts, created_at) "
            "VALUES (?, ?, ?, 0, ?)",
            (user_id, otp_digest(otp), _stamp(expires_at), _stamp(now))
        )
        conn.commit()
        return otp
    finally:
        conn.close()


def verify_reset_otp(email: str, otp_str: str):
    """Verify submitted OTP for the given user email.

    Returns tuple (success: bool, message_or_user_id: Union[str, int])
    """
    clean_email = (email or "").strip().lower()
    clean_otp = (otp_str or "").strip()

    if not clean_email or not clean_otp:
        return False, "Email and 6-digit verification code are required."

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        user_row = conn.execute(
            "SELECT id FROM users WHERE lower(email)=?",
            (clean_email,)
        ).fetchone()

        if not user_row:
            return False, "Invalid or expired verification code."

        user_id = user_row["id"]
        otp_row = conn.execute(
            "SELECT * FROM password_reset_otps WHERE user_id=? AND used_at IS NULL ORDER BY id DESC LIMIT 1",
            (user_id,)
        ).fetchone()

        if not otp_row:
            return False, "Invalid or expired verification code."

        attempts = int(otp_row["attempts"] or 0)
        now_time = _now()
        expires_time = datetime.strptime(otp_row["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

        # Requirement 4 & 5: Check expiry
        if expires_time <= now_time:
            conn.execute(
                "UPDATE password_reset_otps SET used_at=? WHERE id=?",
                (_stamp(now_time), otp_row["id"])
            )
            conn.commit()
            return False, "Invalid or expired verification code."

        # Requirement 10: Check attempt limit
        if attempts >= MAX_OTP_ATTEMPTS:
            conn.execute(
                "UPDATE password_reset_otps SET used_at=? WHERE id=?",
                (_stamp(now_time), otp_row["id"])
            )
            conn.commit()
            return False, "Maximum verification attempts exceeded. Please request a new code."

        # Compare secure hash
        submitted_hash = otp_digest(clean_otp)
        if submitted_hash != otp_row["otp_hash"]:
            new_attempts = attempts + 1
            if new_attempts >= MAX_OTP_ATTEMPTS:
                # Invalidate OTP on attempt limit reached
                conn.execute(
                    "UPDATE password_reset_otps SET attempts=?, used_at=? WHERE id=?",
                    (new_attempts, _stamp(now_time), otp_row["id"])
                )
                conn.commit()
                return False, "Maximum verification attempts exceeded. Please request a new code."
            else:
                conn.execute(
                    "UPDATE password_reset_otps SET attempts=? WHERE id=?",
                    (new_attempts, otp_row["id"])
                )
                conn.commit()
                remaining = MAX_OTP_ATTEMPTS - new_attempts
                return False, f"Invalid verification code. {remaining} attempt(s) remaining."

        # OTP is valid!
        return True, user_id
    finally:
        conn.close()


def complete_reset_by_otp(user_id: int, password_hash: str, source_ip: str = ""):
    """Atomically update password, reset failed attempts & account_locked, invalidate OTPs, and write audit log."""
    now = _stamp(_now())
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        # Requirement 13: Reset failed attempts, unlock account, update password
        cursor.execute(
            "UPDATE users SET password=?, failed_attempts=0, account_locked=0, updated_at=? WHERE id=?",
            (password_hash, now, user_id)
        )
        # Requirement 13 & 5: Invalidate all active OTPs for this user
        cursor.execute(
            "UPDATE password_reset_otps SET used_at=? WHERE user_id=? AND used_at IS NULL",
            (now, user_id)
        )
        cursor.execute(
            "UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL",
            (now, user_id)
        )
        # Requirement 13: Write existing audit event for password reset completion
        cursor.execute(
            "INSERT INTO audit_logs (user_id, username, action, timestamp, ip_address, description) "
            "SELECT id, username, 'PASSWORD_RESET_COMPLETED', ?, ?, 'Password reset completed' "
            "FROM users WHERE id=?",
            (now, source_ip, user_id)
        )
        conn.commit()
        return user_id
    finally:
        conn.close()


def create_reset_token(user_id):
    """Legacy token wrapper calling create_reset_otp for backwards compatibility."""
    return create_reset_otp(user_id)


def valid_reset_token(token):
    """Legacy token validation helper."""
    if not isinstance(token, str) or len(token) < 6:
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM password_reset_otps WHERE otp_hash=? AND used_at IS NULL ORDER BY id DESC LIMIT 1",
            (otp_digest(token),)
        ).fetchone()
        if not row:
            # Fallback check legacy tokens table
            row = conn.execute(
                "SELECT * FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL",
                (token_digest(token),)
            ).fetchone()
            if not row:
                return None
        expires = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dict(row) if expires > _now() else None
    finally:
        conn.close()


def complete_reset(token, password_hash, source_ip=""):
    """Legacy complete_reset wrapper."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        user_row = None
        if len(token) == 6 and token.isdigit():
            user_row = conn.execute(
                "SELECT user_id FROM password_reset_otps WHERE otp_hash=? AND used_at IS NULL",
                (otp_digest(token),)
            ).fetchone()
        if not user_row:
            user_row = conn.execute(
                "SELECT user_id FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL",
                (token_digest(token),)
            ).fetchone()
        if not user_row:
            return None
        return complete_reset_by_otp(user_row["user_id"], password_hash, source_ip)
    finally:
        conn.close()


def audit_reset_request(user_id, source_ip=""):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO audit_logs (user_id, username, action, timestamp, ip_address, description) "
            "SELECT id, username, 'PASSWORD_RESET_REQUESTED', ?, ?, 'Password reset requested' "
            "FROM users WHERE id=?",
            (_stamp(_now()), source_ip, user_id)
        )
        conn.commit()
    finally:
        conn.close()


def audit_invalid_reset(source_ip=""):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO audit_logs (user_id, username, action, timestamp, ip_address, description) "
            "VALUES (0, 'anonymous', 'PASSWORD_RESET_INVALID_TOKEN', ?, ?, 'Invalid or expired password reset code')",
            (_stamp(_now()), source_ip)
        )
        conn.commit()
    finally:
        conn.close()
