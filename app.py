import hashlib
import json
import os
import secrets
import sqlite3
import time
import re
import smtplib
from email.message import EmailMessage
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from user_agents import parse
from werkzeug.security import check_password_hash, generate_password_hash

from database.database import create_database
from prediction.predict import predict_login
from services.auth_event_service import process_auth_event
from services.feature_service import extract_login_features
from services.incident_service import (
    get_incident_by_id,
    get_soc_summary,
    get_recent_events,
    list_incidents,
    update_incident_status,
    assign_incident,
    add_incident_note,
    get_soc_metrics,
)
from services.password_reset_service import (
    RESET_OTP_TTL_MINUTES, RESET_TOKEN_TTL_MINUTES, audit_invalid_reset, audit_reset_request,
    complete_reset, complete_reset_by_otp, create_reset_otp, create_reset_token,
    valid_reset_token, verify_reset_otp,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Load .env configuration before reading any environment variables ─────────
dotenv_path = os.path.join(BASE_DIR, ".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
else:
    load_dotenv()

DB_PATH = os.getenv("DATABASE_PATH", os.path.join(BASE_DIR, "database.db"))

app = Flask(__name__)
app.config["DEBUG"] = False
# Never ship a reusable development secret. Deployments set SECRET_KEY; a local
# fallback is intentionally ephemeral and invalidates sessions after restart.
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"}
app.config["PERMANENT_SESSION_LIFETIME"] = 1800
app.config["API_RATE_LIMIT_PER_MINUTE"] = int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "100"))


def load_mail_config(flask_app=None):
    """(Re)load mail configuration from environment variables into Flask app config."""
    target_app = flask_app or app
    target_app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "").strip()
    target_app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
    target_app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "").strip()
    target_app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "")
    target_app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
    target_app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "").strip()
    if "MAIL_OUTBOX" not in target_app.config:
        target_app.config["MAIL_OUTBOX"] = []


load_mail_config(app)


def get_smtp_diagnostic(flask_app=None):
    """Return diagnostic details of the current SMTP configuration.

    SECURITY NOTE: MAIL_PASSWORD is NEVER returned, displayed, or logged.
    Only a boolean flag indicating whether a password is configured is exposed.
    """
    target_app = flask_app or app
    server = (target_app.config.get("MAIL_SERVER") or "").strip()
    port = int(target_app.config.get("MAIL_PORT", 587))
    use_tls = bool(target_app.config.get("MAIL_USE_TLS", True))
    username = (target_app.config.get("MAIL_USERNAME") or "").strip()
    default_sender = (target_app.config.get("MAIL_DEFAULT_SENDER") or "").strip()
    has_password = bool(target_app.config.get("MAIL_PASSWORD", ""))

    is_configured = bool(server)
    effective_sender = default_sender or username or "no-reply@securecloud.local"

    return {
        "smtp_configured": is_configured,
        "delivery_mode": "SMTP" if is_configured else "DEV_MODE (MAIL_OUTBOX)",
        "mail_server": server if server else "(none - dev mode)",
        "mail_port": port,
        "mail_use_tls": use_tls,
        "mail_username": username if username else "(none)",
        "mail_default_sender": effective_sender,
        "mail_password_configured": has_password,
    }


def log_smtp_status(flask_app=None):
    """Log startup diagnostic information about SMTP configuration without disclosing secrets."""
    target_app = flask_app or app
    diag = get_smtp_diagnostic(target_app)
    if diag["smtp_configured"]:
        target_app.logger.info(
            "[SMTP CONFIG] Real email delivery ENABLED -> Server: %s:%d | STARTTLS: %s | User: %s | Sender: %s | Password: [PROTECTED/%s]",
            diag["mail_server"],
            diag["mail_port"],
            diag["mail_use_tls"],
            diag["mail_username"],
            diag["mail_default_sender"],
            "CONFIGURED" if diag["mail_password_configured"] else "NOT SET",
        )
    else:
        target_app.logger.info(
            "[SMTP CONFIG] DEV MODE active: MAIL_SERVER is empty. Reset emails will be retained in app.config['MAIL_OUTBOX']."
        )


log_smtp_status(app)

create_database(DB_PATH)

API_RATE_LIMIT_BUCKETS = {}
PASSWORD_RESET_RATE_BUCKETS = {}


def _password_is_valid(password):
    return isinstance(password, str) and len(password) >= 8


def _reset_rate_limited(key, limit=5, seconds=3600):
    now = time.time()
    bucket = PASSWORD_RESET_RATE_BUCKETS.setdefault(key, [])
    bucket[:] = [stamp for stamp in bucket if now - stamp < seconds]
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


def _send_password_reset_email(recipient, otp):
    """Send a password-reset 6-digit OTP email via SMTP when configured."""
    subject = "SecureCloud Access Monitoring - Password Reset Code"
    sender = (app.config.get("MAIL_DEFAULT_SENDER")
              or app.config.get("MAIL_USERNAME")
              or "no-reply@securecloud.local")

    body = (
        "Your password reset code is:\n\n"
        f"{otp}\n\n"
        f"This code expires in {RESET_OTP_TTL_MINUTES} minutes.\n\n"
        "If you did not request a password reset, please ignore this email."
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["To"]      = recipient
    message["From"]    = sender
    message.set_content(body)

    # ── Development / test mode ───────────────────────────────────────────────
    mail_server = (app.config.get("MAIL_SERVER") or "").strip()
    if not mail_server:
        if "MAIL_OUTBOX" not in app.config:
            app.config["MAIL_OUTBOX"] = []
        app.config["MAIL_OUTBOX"].append({
            "to":        recipient,
            "subject":   subject,
            "body":      body,
            "otp":       otp,
            "reset_url": f"http://localhost:5000/verify-otp?otp={otp}",
        })
        app.logger.warning(
            "[DEV MODE] Password reset email was NOT sent via SMTP. "
            "OTP retained in app.config['MAIL_OUTBOX']. "
            "Set MAIL_SERVER in .env to enable real email delivery."
        )
        return

    # ── Real SMTP delivery ────────────────────────────────────────────────────
    mail_port = int(app.config.get("MAIL_PORT", 587))
    with smtplib.SMTP(mail_server, mail_port, timeout=15) as smtp:
        smtp.ehlo()
        if app.config.get("MAIL_USE_TLS", True):
            smtp.starttls()
            smtp.ehlo()
        if app.config.get("MAIL_USERNAME"):
            smtp.login(app.config["MAIL_USERNAME"], app.config.get("MAIL_PASSWORD", ""))
        smtp.send_message(message)
    app.logger.info("Password reset code delivered via SMTP to %s", recipient)


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256((raw_key or "").encode("utf-8")).hexdigest()


def _is_rate_limited(application_id: str) -> bool:
    limit = int(app.config.get("API_RATE_LIMIT_PER_MINUTE", 100))
    now = time.time()
    bucket = API_RATE_LIMIT_BUCKETS.setdefault(application_id, [])
    bucket[:] = [ts for ts in bucket if now - ts < 60]
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


def _get_registered_application(application_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM applications WHERE application_id=?",
        (application_id,),
    ).fetchone()
    conn.close()
    return row


def _page_args():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = request.args.get("per_page", 20, type=int)
    return page, per_page if per_page in {20, 50, 100} else 20


def _require_admin_api():
    return bool(session.get("username") == "admin")


def _valid_analyst(username):
    """Assignments are limited to existing administrator/analyst accounts."""
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        return False
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT 1 FROM users WHERE username=? AND COALESCE(role, 'user') IN ('admin', 'analyst')", (username,)).fetchone()
    conn.close()
    return row is not None


def _ensure_demo_application():
    app_id = "secure-cloud-demo"
    existing = _get_registered_application(app_id)
    if existing is None:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        api_key = secrets.token_urlsafe(24)
        cursor.execute(
            """
            INSERT INTO applications (application_id, application_name, description, api_key_hash, status, created_at, owner)
            VALUES (?, ?, ?, ?, 'active', datetime('now'), 'admin')
            """,
            (app_id, "Secure Cloud Demo", "Built-in demo client application", _hash_api_key(api_key)),
        )
        conn.commit()
        conn.close()
    return app_id


def _get_application_stats(application_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT application_id, application_name, description, owner, status, created_at, last_event_at,
               COALESCE(total_events, 0) AS total_events,
               COALESCE(high_risk_events, 0) AS high_risk_events,
               COALESCE(medium_risk_events, 0) AS medium_risk_events,
               COALESCE(low_risk_events, 0) AS low_risk_events
        FROM applications
        WHERE application_id=?
        """,
        (application_id,),
    ).fetchone()
    conn.close()
    return row


def _get_monitored_application_summary():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT COUNT(*) AS total_applications,
               SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active_applications,
               SUM(CASE WHEN status='revoked' THEN 1 ELSE 0 END) AS revoked_applications,
               SUM(CASE WHEN last_event_at >= date('now') THEN 1 ELSE 0 END) AS apps_active_today
        FROM applications
        """
    ).fetchone()
    events_today = conn.execute(
        "SELECT COUNT(*) FROM auth_events WHERE datetime(timestamp) >= datetime('now', 'start of day')"
    ).fetchone()[0]
    high_risk_events = conn.execute("SELECT COUNT(*) FROM auth_events WHERE risk_level='HIGH'").fetchone()[0]
    medium_risk_events = conn.execute("SELECT COUNT(*) FROM auth_events WHERE risk_level='MEDIUM'").fetchone()[0]
    recent_apps = conn.execute(
        """
        SELECT application_id, application_name, status, last_event_at, total_events,
               COALESCE(high_risk_events, 0) AS high_risk_events,
               COALESCE(medium_risk_events, 0) AS medium_risk_events,
               COALESCE(low_risk_events, 0) AS low_risk_events
        FROM applications
        WHERE last_event_at IS NOT NULL
        ORDER BY last_event_at DESC
        LIMIT 10
        """
    ).fetchall()
    conn.close()
    return {
        "total_applications": row["total_applications"] or 0,
        "active_applications": row["active_applications"] or 0,
        "events_today": events_today,
        "high_risk_events": high_risk_events,
        "medium_risk_events": medium_risk_events,
        "recent_apps": recent_apps,
    }


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, password, failed_attempts, account_locked, user_code, trusted_device, ai_enabled
            FROM users WHERE username=?
            """,
            (username,),
        )
        user = cursor.fetchone()

        if user:
            user_id = user[0]
            db_password = user[2]
            failed_attempts = user[3]
            account_locked = user[4]
            user_code = user[5]
            ai_enabled = user[7]

            if account_locked == 1:
                conn.close()
                flash("Your account is locked. Contact the administrator.", "error")
                return render_template("login.html")

            if not check_password_hash(db_password, password):
                failed_attempts += 1
                if failed_attempts >= 3:
                    cursor.execute(
                        "UPDATE users SET failed_attempts=?, account_locked=1 WHERE id=?",
                        (failed_attempts, user_id),
                    )
                    conn.commit()
                    conn.close()
                    flash("Account locked after 3 failed login attempts.", "error")
                    return render_template("login.html")

                cursor.execute(
                    "UPDATE users SET failed_attempts=? WHERE id=?",
                    (failed_attempts, user_id),
                )
                conn.commit()
                conn.close()
                flash(f"Invalid password. {3 - failed_attempts} attempt(s) remaining.", "error")
                return render_template("login.html")

            cursor.execute(
                "UPDATE users SET failed_attempts=0, account_locked=0 WHERE id=?",
                (user_id,),
            )
            conn.commit()
            session["username"] = username

            now = datetime.now()
            ip_address = request.remote_addr
            user_agent = parse(request.headers.get("User-Agent"))
            browser = user_agent.browser.family
            device = user_agent.os.family
            hour = now.hour
            day = now.day
            month = now.month
            weekday = now.weekday()

            if username == "admin":
                activity = 5
            elif username == "Arun":
                activity = 3
            elif username == "Ramya":
                activity = 2
            elif username == "Harini":
                activity = 4
            else:
                activity = 1

            pc_id = user[6]
            application_id = _ensure_demo_application()

            if ai_enabled == 1:
                behavioural_features = extract_login_features(
                    username=username,
                    user_id=user_id,
                    user_code=user_code,
                    pc_id=pc_id,
                    ip_address=ip_address,
                    device=device,
                    browser=browser,
                    hour=hour,
                    day=day,
                    month=month,
                    weekday=weekday,
                )
                prediction = predict_login(
                    user=user_code,
                    pc=pc_id,
                    activity=activity,
                    hour=hour,
                    day=day,
                    month=month,
                    weekday=weekday,
                    behavioural_features=behavioural_features,
                )
            else:
                prediction = {"prediction": "Normal Login", "risk": "LOW", "reasons": ["AI Threat Detection is disabled"]}

            event_record = {
                "application_id": application_id,
                "user_id": username,
                "timestamp": now.isoformat(timespec="seconds"),
                "ip_address": ip_address,
                "device_id": device,
                "browser": browser,
                "os": user_agent.os.family,
                "login_success": True,
                "failed_attempts": 0,
            }
            processed = process_auth_event(event_record, api_key=None, allow_missing_application=True)
            if processed.get("risk_level"):
                prediction["risk"] = processed["risk_level"]
                prediction["prediction"] = processed["prediction"]
                prediction["threat_score"] = processed.get("threat_score", prediction.get("threat_score", 0.0))
                prediction["confidence"] = processed.get("confidence", 0.0)
                prediction["reasons"] = processed.get("reasons", prediction.get("reasons", []))

            cursor.execute(
                """
                INSERT INTO login_logs (username, login_date, login_time, ip_address, browser, device, prediction, risk, reasons)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (username, now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S"), ip_address, browser, device, prediction["prediction"], prediction["risk"], json.dumps(prediction["reasons"]))
            )
            conn.commit()
            conn.close()
            session["prediction"] = prediction
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("admin" if username == "admin" else "dashboard"))

        conn.close()
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    generic_message = "If an account exists for this email, a password reset code has been sent."
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("Email is required.", "error")
            return render_template("forgot_password.html")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
            flash("Enter a valid email address.", "error")
            return render_template("forgot_password.html")

        ip_address = request.remote_addr or ""
        email_key = "email:" + hashlib.sha256(email.encode("utf-8")).hexdigest()
        if not _reset_rate_limited("ip:" + ip_address) and not _reset_rate_limited(email_key):
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            user = conn.execute("SELECT id, email FROM users WHERE lower(email)=?", (email,)).fetchone()
            conn.close()
            if user:
                otp = create_reset_otp(user["id"])
                try:
                    _send_password_reset_email(user["email"], otp)
                    audit_reset_request(user["id"], ip_address)
                except (OSError, smtplib.SMTPException):
                    # Deliberately identical response prevents enumeration and mail-config leakage.
                    app.logger.error("Password reset delivery failed without disclosing account details.")
        session["reset_email"] = email
        flash(generic_message, "success")
        return redirect(url_for("verify_otp"))
    return render_template("forgot_password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("reset_email", "")
    if request.method == "POST":
        email = request.form.get("email", email).strip().lower()
        otp = request.form.get("otp", "").strip()
        if not email:
            flash("Email is required.", "error")
            return render_template("verify_otp.html", email=email)
        if not otp:
            flash("6-digit verification code is required.", "error")
            return render_template("verify_otp.html", email=email)

        success, result = verify_reset_otp(email, otp)
        if not success:
            audit_invalid_reset(request.remote_addr or "")
            flash(result, "error")
            return render_template("verify_otp.html", email=email)

        # Verification successful
        user_id = result
        session["otp_verified_user_id"] = user_id
        session["reset_email"] = email
        flash("Code verified successfully. Please set your new password.", "success")
        return redirect(url_for("reset_password"))

    return render_template("verify_otp.html", email=email)


@app.route("/reset-password", methods=["GET", "POST"])
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token=None):
    user_id = session.get("otp_verified_user_id")
    if token and not user_id:
        token_record = valid_reset_token(token)
        if token_record:
            user_id = token_record["user_id"]
            session["otp_verified_user_id"] = user_id
        else:
            audit_invalid_reset(request.remote_addr or "")
            flash("This password reset link is invalid or has expired.", "error")
            return redirect(url_for("forgot_password"))

    if not user_id:
        flash("Please verify your reset code first.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if not _password_is_valid(password):
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", token=token)
        if password != confirmation:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", token=token)

        res = complete_reset_by_otp(user_id, generate_password_hash(password), request.remote_addr or "")
        if res is None:
            audit_invalid_reset(request.remote_addr or "")
            flash("This password reset link is invalid or has expired.", "error")
            return redirect(url_for("forgot_password"))

        session.clear()
        flash("Your password has been reset. Please sign in with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if username and email and password:
            if not _password_is_valid(password):
                flash("Password must be at least 8 characters.", "error")
                return render_template("register.html")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                conn.close()
                flash("Username already exists.", "error")
                return render_template("register.html")

            hashed_password = generate_password_hash(password)
            try:
                cursor.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                flash("Email already registered.", "error")
                return render_template("register.html")
            conn.close()

            session["username"] = username
            flash(f"Account created successfully! Welcome, {username}.", "success")
            return redirect(url_for("dashboard"))

        flash("Please fill in all required fields.", "error")

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    username = session.get("username")
    prediction = session.get("prediction")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT ai_enabled FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    ai_enabled = user["ai_enabled"] if user else 0

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE login_date = date('now')")
    today_logins = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk='HIGH'")
    blocked_attempts = cursor.fetchone()[0]
    threat_alerts = blocked_attempts

    cursor.execute(
        """
        SELECT username, ip_address, device, browser, prediction, risk, login_time
        FROM login_logs ORDER BY id DESC LIMIT 10
        """
    )
    recent_logins = cursor.fetchall()
    conn.close()

    class SimpleUser:
        def __init__(self, name):
            self.username = name

    current_user = SimpleUser(username)

    if ai_enabled == 1 and prediction:
        threat_score = float(prediction.get("threat_score", 0.0))
        confidence = float(prediction.get("confidence", 0.0))
        threat_level = prediction.get("risk", "LOW")
        ai_prediction = prediction.get("prediction", "Normal Login")
        prediction_reasons = prediction.get("reasons", [])
    else:
        threat_score = 0.0
        confidence = 0.0
        threat_level = "DISABLED"
        ai_prediction = "AI Threat Detection is disabled"
        prediction_reasons = ["AI Threat Detection is disabled for this account."]

    monitored = _get_monitored_application_summary()
    return render_template(
        "dashboard.html",
        current_user=current_user,
        total_users=total_users,
        today_logins=today_logins,
        blocked_attempts=blocked_attempts,
        threat_alerts=threat_alerts,
        notification_count=7,
        recent_logins=recent_logins,
        ai_enabled=ai_enabled,
        threat_level=threat_level,
        ai_prediction=ai_prediction,
        confidence=confidence,
        threat_score=threat_score,
        prediction_reasons=prediction_reasons,
        monitored_apps=monitored,
    )


@app.route("/admin")
def admin():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    if session["username"] != "admin":
        flash("Access Denied!", "error")
        return redirect(url_for("dashboard"))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_logs")
    total_logins = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk='HIGH'")
    high_risk = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM users WHERE account_locked = 1")
    locked_accounts = cursor.fetchone()[0]
    cursor.execute("SELECT id, username, email, failed_attempts, account_locked FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    conn.close()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    app_cursor = conn.cursor()
    app_cursor.execute(
        """
        SELECT application_id, application_name, status, last_event_at, total_events,
               (SELECT COUNT(*) FROM auth_events WHERE application_id = applications.application_id AND risk_level = 'HIGH') AS high_risk_events
        FROM applications ORDER BY id DESC
        """
    )
    applications = app_cursor.fetchall()
    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_logins=total_logins,
        high_risk=high_risk,
        locked_accounts=locked_accounts,
        users=users,
        applications=applications,
    )


@app.route("/admin/applications", methods=["GET", "POST"])
def admin_applications():
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        application_id = request.form.get("application_id", "").strip()
        application_name = request.form.get("application_name", "").strip()
        description = request.form.get("description", "").strip()
        owner = request.form.get("owner", "admin").strip() or "admin"
        if not application_id or not application_name:
            flash("Application ID and name are required.", "error")
            return redirect(url_for("admin_applications"))

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM applications WHERE application_id=?", (application_id,))
        if cursor.fetchone():
            conn.close()
            flash("Application ID already exists.", "error")
            return redirect(url_for("admin_applications"))

        api_key = secrets.token_urlsafe(24)
        cursor.execute(
            """
            INSERT INTO applications (application_id, application_name, description, owner, api_key_hash, status, created_at, total_events, high_risk_events, medium_risk_events, low_risk_events)
            VALUES (?, ?, ?, ?, ?, 'active', datetime('now'), 0, 0, 0, 0)
            """,
            (application_id, application_name, description, owner, _hash_api_key(api_key)),
        )
        conn.commit()
        conn.close()
        flash(f"Application registered. New API key: {api_key}. Store it securely and keep it private.", "success")
        return redirect(url_for("admin_applications"))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT application_id, application_name, owner, description, status, last_event_at, total_events,
               COALESCE(high_risk_events, 0) AS high_risk_events,
               COALESCE(medium_risk_events, 0) AS medium_risk_events,
               COALESCE(low_risk_events, 0) AS low_risk_events
        FROM applications
        ORDER BY id DESC
        """
    ).fetchall()
    conn.close()
    summary = _get_monitored_application_summary()
    return render_template("admin_applications.html", applications=rows, summary=summary)


@app.route("/admin/applications/<application_id>")
def application_detail(application_id):
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    app_record = _get_application_stats(application_id)
    if app_record is None:
        flash("Application not found.", "error")
        return redirect(url_for("admin_applications"))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    events = conn.execute(
        """
        SELECT username, timestamp, ip_address, device_id, browser, risk_level, model_probability, risk_score, prediction, reasons
        FROM auth_events
        WHERE application_id=?
        ORDER BY id DESC
        LIMIT 25
        """,
        (application_id,),
    ).fetchall()
    high_risk_events = conn.execute("SELECT COUNT(*) FROM auth_events WHERE application_id=? AND risk_level='HIGH'", (application_id,)).fetchone()[0]
    medium_risk_events = conn.execute("SELECT COUNT(*) FROM auth_events WHERE application_id=? AND risk_level='MEDIUM'", (application_id,)).fetchone()[0]
    low_risk_events = conn.execute("SELECT COUNT(*) FROM auth_events WHERE application_id=? AND risk_level='LOW'", (application_id,)).fetchone()[0]
    recent_alerts = conn.execute(
        "SELECT username, alert_type, severity, alert_time, message, threat_score FROM security_alerts WHERE username IN (SELECT username FROM auth_events WHERE application_id=?) AND created_at IS NOT NULL ORDER BY id DESC LIMIT 10",
        (application_id,),
    ).fetchall()
    top_users = conn.execute(
        "SELECT username, COUNT(*) AS event_count FROM auth_events WHERE application_id=? GROUP BY username ORDER BY event_count DESC LIMIT 5",
        (application_id,),
    ).fetchall()
    top_ips = conn.execute(
        "SELECT ip_address, COUNT(*) AS count FROM auth_events WHERE application_id=? GROUP BY ip_address ORDER BY count DESC LIMIT 5",
        (application_id,),
    ).fetchall()
    conn.close()

    return render_template(
        "application_detail.html",
        app=app_record,
        events=events,
        stats={"high": high_risk_events, "medium": medium_risk_events, "low": low_risk_events},
        recent_alerts=recent_alerts,
        top_users=top_users,
        top_ips=top_ips,
    )


@app.route("/admin/applications/<application_id>/toggle", methods=["POST"])
def toggle_application(application_id):
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM applications WHERE application_id=?", (application_id,))
    row = cursor.fetchone()
    if row:
        new_status = "inactive" if row[0] == "active" else "active"
        cursor.execute("UPDATE applications SET status=? WHERE application_id=?", (new_status, application_id))
        conn.commit()
        flash(f"Application status changed to {new_status}.", "success")
    conn.close()
    return redirect(url_for("admin_applications"))


@app.route("/admin/applications/<application_id>/rotate", methods=["POST"])
def rotate_application_key(application_id):
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    api_key = secrets.token_urlsafe(24)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE applications SET api_key_hash=? WHERE application_id=?", (_hash_api_key(api_key), application_id))
    conn.commit()
    conn.close()
    flash(f"API key rotated. New key: {api_key}. Store it securely and keep it private.", "success")
    return redirect(url_for("admin_applications"))


@app.route("/admin/applications/<application_id>/revoke", methods=["POST"])
def revoke_application(application_id):
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE applications SET status='revoked' WHERE application_id=?", (application_id,))
    conn.commit()
    conn.close()
    flash("Application access revoked.", "success")
    return redirect(url_for("admin_applications"))


@app.route("/unlock/<int:user_id>")
def unlock_user(user_id):
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET failed_attempts=0, account_locked=0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash("User account unlocked successfully.", "success")
    return redirect(url_for("admin"))


@app.route("/profile")
def profile():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    username = session["username"]
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, username, email, user_code, trusted_device, failed_attempts, account_locked
        FROM users WHERE username=?
        """,
        (username,),
    )
    user = cursor.fetchone()
    conn.close()
    if not user:
        flash("User account not found.", "error")
        return redirect(url_for("login"))
    return render_template("profile.html", user=user)


@app.route("/toggle-ai", methods=["POST"])
def toggle_ai():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT ai_enabled FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user:
        new_status = 0 if user[0] == 1 else 1
        cursor.execute("UPDATE users SET ai_enabled=? WHERE username=?", (new_status, username))
        conn.commit()
        flash("AI Threat Detection enabled." if new_status == 1 else "AI Threat Detection disabled.", "success" if new_status == 1 else "error")
    conn.close()
    return redirect(url_for("settings"))


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if request.method == "POST":
        ai_enabled = 1 if request.form.get("ai_enabled") == "on" else 0
        cursor.execute("UPDATE users SET ai_enabled=? WHERE username=?", (ai_enabled, username))
        conn.commit()
        flash("AI Threat Detection setting updated.", "success")

    cursor.execute(
        """
        SELECT id, username, email, user_code, trusted_device, failed_attempts, account_locked, ai_enabled
        FROM users WHERE username=?
        """,
        (username,),
    )
    user = cursor.fetchone()
    conn.close()
    if not user:
        flash("User account not found.", "error")
        return redirect(url_for("login"))
    return render_template("settings.html", user=user)


@app.route("/threat-detection")
def threat_detection():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    return render_template("threat_detection.html")


@app.route("/ai-prediction")
def ai_prediction():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    return render_template("ai_prediction.html")


@app.route("/security-alerts")
def security_alerts():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    return render_template("security_alerts.html")


@app.route("/login-activity")
def login_activity():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    return render_template("login_activity.html")


@app.route("/analytics")
def analytics():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    return render_template("analytics.html")


@app.route("/audit-logs")
def audit_logs():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    return render_template("audit_logs.html")


@app.route("/investigate/")
@app.route("/investigate/<int:alert_id>")
def investigate(alert_id=None):
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    return render_template("investigate.html", alert_id=alert_id)


@app.route("/model-performance")
def model_performance():
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    try:
        with open(os.path.join(BASE_DIR, "models", "model_metadata.json"), "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except Exception as exc:
        return render_template("model_performance.html", perf={"error": str(exc)})

    metrics = metadata.get("metrics", {})
    confusion = metadata.get("confusion_matrix", [[0, 0], [0, 0]])
    tn = confusion[0][0] if len(confusion) > 1 and len(confusion[0]) > 1 else 0
    fp = confusion[0][1] if len(confusion) > 0 and len(confusion[0]) > 1 else 0
    fn = confusion[1][0] if len(confusion) > 1 else 0
    tp = confusion[1][1] if len(confusion) > 1 and len(confusion[1]) > 1 else 0

    perf = {
        "accuracy": round(float(metrics.get("accuracy", 0.0)) * 100, 2),
        "precision": round(float(metrics.get("precision", 0.0)) * 100, 2),
        "recall": round(float(metrics.get("recall", 0.0)) * 100, 2),
        "f1": round(float(metrics.get("f1", 0.0)) * 100, 2),
        "roc_auc": round(float(metrics.get("roc_auc", 0.0)) * 100, 2),
        "brier_score": round(float(metrics.get("brier_score", 0.0)), 4),
        "version": metadata.get("version", "unknown"),
        "algorithm": metadata.get("algorithm", "Unknown"),
        "train_date": metadata.get("train_date", "unknown"),
        "train_samples": metadata.get("train_samples", 0),
        "test_samples": metadata.get("test_samples", 0),
        "feature_count": metadata.get("feature_count", 0),
        "label_type": metadata.get("label_type", "unknown"),
        "feature_names": metadata.get("features", []),
        "scoring_weights": metadata.get("scoring_weights", {}),
        "design_note": metadata.get("design_note", ""),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }
    return render_template("model_performance.html", perf=perf)


@app.route("/api/v1/auth-events", methods=["POST"])
def api_auth_events():
    if not request.is_json:
        return jsonify({"error": "Request body must be JSON."}), 400

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Malformed JSON body."}), 400

    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return jsonify({"error": "Missing X-API-Key header."}), 401

    application_id = str(payload.get("application_id", "")).strip()
    app_record = _get_registered_application(application_id) if application_id else None
    if app_record is None:
        return jsonify({"error": "Application is not registered."}), 403
    if app_record["status"] == "revoked":
        return jsonify({"error": "Application is revoked."}), 403

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM applications WHERE api_key_hash=? AND status IN ('active', 'inactive')",
        (_hash_api_key(api_key),),
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "Invalid or revoked API key."}), 401
    if row["application_id"] != application_id:
        return jsonify({"error": "API key does not belong to this application."}), 403
    if row["status"] == "inactive":
        return jsonify({"error": "Application is disabled."}), 403

    if _is_rate_limited(row["application_id"]):
        return jsonify({"error": "Rate limit exceeded."}), 429

    try:
        result = process_auth_event(payload, api_key=api_key)
        return jsonify(result), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except PermissionError:
        return jsonify({"error": "API authentication failed."}), 401
    except LookupError:
        return jsonify({"error": "Application not registered or unauthorized."}), 403
    except Exception:
        return jsonify({"error": "Event ingestion failed."}), 500


@app.route("/api-docs")
def api_docs():
    return render_template("api_docs.html")


@app.route("/api/v1/events")
@app.route("/api/v1/soc/events")
def api_events():
    if not _require_admin_api():
        return jsonify({"error": "Administrator authentication required."}), 403
    page, per_page = _page_args()
    filters, params = [], []
    for column, arg in (("application_id", "application"), ("risk_level", "risk"), ("username", "user"), ("ip_address", "ip"), ("status", "status")):
        if request.args.get(arg): filters.append(f"{column}=?"); params.append(request.args[arg])
    clause = " WHERE " + " AND ".join(filters) if filters else ""
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    total = conn.execute("SELECT COUNT(*) FROM auth_events" + clause, params).fetchone()[0]
    rows = conn.execute("SELECT * FROM auth_events" + clause + " ORDER BY timestamp DESC LIMIT ? OFFSET ?", params + [per_page, (page-1)*per_page]).fetchall(); conn.close()
    return jsonify({"items": [dict(r) for r in rows], "page": page, "per_page": per_page, "total": total})


@app.route("/api/v1/alerts")
@app.route("/api/v1/soc/alerts")
def api_alerts():
    if not _require_admin_api(): return jsonify({"error": "Administrator authentication required."}), 403
    page, per_page = _page_args(); clauses, params = [], []
    for column, arg in (("application_id", "application"), ("severity", "severity"), ("status", "status")):
        if request.args.get(arg): clauses.append(f"{column}=?"); params.append(request.args[arg])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    total = conn.execute("SELECT COUNT(*) FROM security_alerts" + where, params).fetchone()[0]
    rows = conn.execute("SELECT * FROM security_alerts" + where + " ORDER BY created_at DESC LIMIT ? OFFSET ?", params+[per_page,(page-1)*per_page]).fetchall(); conn.close()
    return jsonify({"items": [dict(r) for r in rows], "page": page, "per_page": per_page, "total": total})


@app.route("/api/v1/incidents")
@app.route("/api/v1/soc/incidents")
def api_incidents():
    if not _require_admin_api(): return jsonify({"error": "Administrator authentication required."}), 403
    page, per_page = _page_args()
    rows, total = list_incidents({"application_id": request.args.get("application"), "severity": request.args.get("severity"), "status": request.args.get("status")}, per_page, (page-1)*per_page)
    return jsonify({"items": rows, "page": page, "per_page": per_page, "total": total, "metrics": get_soc_metrics()})


@app.route("/api/v1/incidents/<incident_id>")
@app.route("/api/v1/soc/incidents/<incident_id>")
def api_incident_detail(incident_id):
    if not _require_admin_api(): return jsonify({"error": "Administrator authentication required."}), 403
    incident = get_incident_by_id(incident_id)
    return (jsonify(incident), 200) if incident else (jsonify({"error": "Incident not found."}), 404)


@app.route("/api/v1/incidents/<incident_id>/assign", methods=["POST"])
@app.route("/api/v1/soc/incidents/<incident_id>/assign", methods=["POST"])
def api_incident_assign(incident_id):
    if not _require_admin_api(): return jsonify({"error": "Administrator authentication required."}), 403
    body = request.get_json(silent=True) or {}; analyst = str(body.get("analyst", "")).strip()
    if not _valid_analyst(analyst): return jsonify({"error": "analyst must be an existing analyst or administrator."}), 400
    return jsonify({"success": assign_incident(incident_id, analyst, session["username"])}), 200


@app.route("/api/v1/incidents/<incident_id>/status", methods=["POST"])
@app.route("/api/v1/soc/incidents/<incident_id>/status", methods=["POST"])
def api_incident_status(incident_id):
    if not _require_admin_api(): return jsonify({"error": "Administrator authentication required."}), 403
    body = request.get_json(silent=True) or {}; status = body.get("status")
    if status not in {"NEW", "TRIAGED", "ACKNOWLEDGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"}: return jsonify({"error": "status is invalid."}), 400
    ok = update_incident_status(incident_id, status, body.get("resolution_notes", ""), session["username"], body.get("comment", ""))
    return (jsonify({"success": True}), 200) if ok else (jsonify({"error": "Invalid status transition or incident."}), 400)


@app.route("/api/v1/incidents/<incident_id>/notes", methods=["POST"])
@app.route("/api/v1/soc/incidents/<incident_id>/notes", methods=["POST"])
def api_incident_notes(incident_id):
    if not _require_admin_api(): return jsonify({"error": "Administrator authentication required."}), 403
    body = request.get_json(silent=True) or {}; note = body.get("note", "")
    if not isinstance(note, str) or not note.strip(): return jsonify({"error": "note is required."}), 400
    return (jsonify({"success": True}), 201) if add_incident_note(incident_id, session["username"], note) else (jsonify({"error": "Unable to add note."}), 400)


@app.route("/api/v1/applications")
def api_applications():
    if not _require_admin_api(): return jsonify({"error": "Administrator authentication required."}), 403
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT a.application_id, a.application_name, a.status, a.last_event_at, a.total_events,
          a.high_risk_events, a.medium_risk_events, a.low_risk_events,
          (SELECT COUNT(*) FROM incidents i WHERE i.application_id=a.application_id AND i.status IN ('NEW','OPEN','TRIAGED','ACKNOWLEDGED','INVESTIGATING','CONTAINED')) AS open_incidents,
          (SELECT MAX(created_at) FROM security_alerts sa WHERE sa.application_id=a.application_id) AS latest_alert
        FROM applications a ORDER BY a.application_name
    """).fetchall(); conn.close()
    return jsonify({"items": [dict(row) for row in rows]})


@app.route("/api/v1/applications/<application_id>/summary")
def api_application_summary(application_id):
    if not _require_admin_api(): return jsonify({"error": "Administrator authentication required."}), 403
    record = _get_application_stats(application_id)
    if record is None: return jsonify({"error": "Application not found."}), 404
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    alerts = conn.execute("SELECT * FROM security_alerts WHERE application_id=? ORDER BY created_at DESC LIMIT 20", (application_id,)).fetchall()
    incidents, total = list_incidents({"application_id": application_id}, 20, 0)
    recent_events = conn.execute("SELECT * FROM auth_events WHERE application_id=? ORDER BY timestamp DESC LIMIT 20", (application_id,)).fetchall(); conn.close()
    return jsonify({"application": dict(record), "events": [dict(row) for row in recent_events], "alerts": [dict(row) for row in alerts], "incidents": incidents, "incident_total": total})


# Phase 9: SOC Monitoring and Incident Response Routes
@app.route("/admin/soc-dashboard")
def soc_dashboard():
    """SOC operations center dashboard with real-time incident overview."""
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    try:
        summary = get_soc_summary()
        recent_events = get_recent_events(limit=20)
        return render_template("soc_dashboard.html", summary=summary, recent_events=recent_events)
    except Exception as e:
        flash(f"Error loading SOC dashboard: {str(e)}", "error")
        return redirect(url_for("admin"))


@app.route("/admin/security-events")
def security_events():
    """Security events timeline with filtering."""
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    try:
        # Get query parameters for filtering
        page = request.args.get("page", 1, type=int)
        page, per_page = _page_args()
        risk_level = request.args.get("risk_level", "")
        application_id = request.args.get("application_id", "")
        username = request.args.get("username", "")

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Build filter query
        query = "SELECT * FROM auth_events WHERE 1=1"
        params = []

        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)
        if application_id:
            query += " AND application_id = ?"
            params.append(application_id)
        if username:
            query += " AND username = ?"
            params.append(username)

        # Count total
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]

        # Get paginated results
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])
        cursor.execute(query, params)
        events = cursor.fetchall()

        # Get unique applications for filter dropdown
        cursor.execute("SELECT DISTINCT application_id FROM applications WHERE status = 'active' ORDER BY application_id")
        applications = [row[0] for row in cursor.fetchall()]

        conn.close()

        total_pages = (total + per_page - 1) // per_page
        return render_template(
            "security_events.html",
            events=events,
            page=page,
            total_pages=total_pages,
            total=total,
            applications=applications,
            filter_risk_level=risk_level,
            filter_application_id=application_id,
            filter_username=username,
        )
    except Exception as e:
        flash(f"Error loading security events: {str(e)}", "error")
        return redirect(url_for("admin"))


@app.route("/admin/incidents")
def incidents():
    """Incident list with filtering."""
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    try:
        page, per_page = _page_args()
        severity = request.args.get("severity", "")
        status = request.args.get("status", "")
        application_id = request.args.get("application_id", "")

        incidents_list, total = list_incidents(
            filters={"severity": severity or None, "status": status or None, "application_id": application_id or None},
            limit=per_page, offset=(page - 1) * per_page,
        )

        # Get unique values for filter dropdowns
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT application_id FROM applications WHERE status = 'active' ORDER BY application_id")
        applications = [row[0] for row in cursor.fetchall()]

        conn.close()

        total_pages = (total + per_page - 1) // per_page
        return render_template(
            "incidents.html",
            incidents=incidents_list,
            page=page,
            total_pages=total_pages,
            total=total,
            applications=applications,
            filter_severity=severity,
            filter_status=status,
            filter_application_id=application_id,
        )
    except Exception as e:
        flash(f"Error loading incidents: {str(e)}", "error")
        return redirect(url_for("admin"))


@app.route("/admin/incidents/<incident_id>")
def incident_detail(incident_id):
    """Incident investigation page with detailed threat analysis."""
    if "username" not in session or session.get("username") != "admin":
        flash("Please login as administrator.", "error")
        return redirect(url_for("login"))

    try:
        incident = get_incident_by_id(incident_id)
        if not incident:
            flash("Incident not found.", "error")
            return redirect(url_for("incidents"))

        return render_template("incident_detail.html", incident=incident)
    except Exception as e:
        flash(f"Error loading incident details: {str(e)}", "error")
        return redirect(url_for("incidents"))


@app.route("/admin/incidents/<incident_id>/assign", methods=["POST"])
def assign_incident_action(incident_id):
    """Assign incident to analyst."""
    if "username" not in session or session.get("username") != "admin":
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    try:
        payload = request.get_json(silent=True) or {}
        analyst = payload.get("analyst")
        if not _valid_analyst(analyst):
            return jsonify({"success": False, "error": "analyst must be an existing analyst or administrator"}), 400

        assign_incident(incident_id, analyst, session["username"])
        return jsonify({"success": True, "message": f"Assigned to {analyst}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/admin/incidents/<incident_id>/status", methods=["POST"])
def update_incident_status_action(incident_id):
    """Update incident status."""
    if "username" not in session or session.get("username") != "admin":
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    try:
        body = request.get_json(silent=True) or {}
        new_status = body.get("status")
        if new_status not in {"NEW", "TRIAGED", "ACKNOWLEDGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"}:
            return jsonify({"success": False, "error": "Invalid status"}), 400

        if not update_incident_status(incident_id, new_status, body.get("resolution_notes", ""), session["username"], body.get("comment", "")):
            return jsonify({"success": False, "error": "Invalid state transition or incident not found"}), 400
        return jsonify({"success": True, "message": f"Status updated to {new_status}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))



if __name__ == "__main__":
    log_smtp_status(app)
    app.run(debug=False, use_reloader=False)
