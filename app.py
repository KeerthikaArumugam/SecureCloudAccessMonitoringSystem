from werkzeug.security import generate_password_hash, check_password_hash
from flask import request
from user_agents import parse
import joblib
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, session
from prediction.predict import predict_login
from datetime import datetime
import random
import sqlite3
import json

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-in-production"

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Connect to database
        conn = sqlite3.connect("database.db", timeout=10)
        cursor = conn.cursor()

        # Find user by username
        cursor.execute("""
        SELECT
            id,
            username,
            password,
            failed_attempts,
            account_locked,
            user_code,
            trusted_device
        FROM users
        WHERE username=?
        """, (username,))


        user = cursor.fetchone()

        # User exists
        if user:

            user_id = user[0]
            db_username = user[1]
            db_password = user[2]
            failed_attempts = user[3]
            account_locked = user[4]
            user_code = user[5]
            pc_id = user[6]
            # Account already locked
            if account_locked == 1:
                conn.close()
                flash("Your account is locked. Contact the administrator.", "error")
                return render_template("login.html")

            # Wrong password
            if not check_password_hash(db_password, password):

                failed_attempts += 1

                if failed_attempts >= 3:

                    cursor.execute("""
                    UPDATE users
                    SET failed_attempts=?, account_locked=1
                    WHERE id=?
                    """, (failed_attempts, user_id))

                    conn.commit()
                    conn.close()

                    flash("Account locked after 3 failed login attempts.", "error")
                    return render_template("login.html")

                else:

                    cursor.execute("""
                    UPDATE users
                    SET failed_attempts=?
                    WHERE id=?
                    """, (failed_attempts, user_id))

                    conn.commit()
                    conn.close()

                    flash(
                        f"Invalid password. {3-failed_attempts} attempt(s) remaining.",
                        "error"
                    )
                    return render_template("login.html")

            # Correct password
            cursor.execute("""
            UPDATE users
            SET failed_attempts=0,
                account_locked=0
            WHERE id=?
            """, (user_id,))

            conn.commit()

            session["username"] = username

            # Current Date & Time
            now = datetime.now()
            ip_address = request.remote_addr

            user_agent = parse(request.headers.get("User-Agent"))

            browser = user_agent.browser.family
            device = user_agent.os.family

            hour = now.hour
            day = now.day
            month = now.month
            weekday = now.weekday()

            # Temporary encoded values
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

            # AI Prediction
            prediction = predict_login(
                user=user_code,
                pc=pc_id,
                activity=activity,
                hour=hour,
                day=day,
                month=month,
                weekday=weekday
            )
            # Save login details
            cursor.execute("""
            INSERT INTO login_logs
            (username, login_date, login_time, ip_address, browser, device, prediction, risk, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                username,
                now.strftime("%Y-%m-%d"),
                now.strftime("%H:%M:%S"),
                ip_address,
                browser,
                device,
                prediction["prediction"],
                prediction["risk"],
                json.dumps(prediction["reasons"])
            ))

            conn.commit()
            conn.close()

            session["prediction"] = prediction

            flash(f"Welcome back, {username}!", "success")

            if username == "admin":
                return redirect(url_for("admin"))
            else:
                return redirect(url_for("dashboard"))

        else:
            conn.close()
            flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if username and email and password:

            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            # Check if username already exists
            cursor.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            )

            existing_user = cursor.fetchone()

            if existing_user:
                conn.close()
                flash("Username already exists.", "error")
                return render_template("register.html")

            # Hash the password
            hashed_password = generate_password_hash(password)

            try:
                cursor.execute("""
                INSERT INTO users (username, email, password)
                VALUES (?, ?, ?)
                """, (
                    username,
                    email,
                    hashed_password
                ))

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
    # User must be logged in
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))


    username = session.get("username")
    prediction = session.get("prediction")

    import sqlite3

    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # -------------------------
    # Dashboard Statistics
    # -------------------------

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM login_logs
    WHERE login_date = date('now')
    """)
    today_logins = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM login_logs
    WHERE risk='HIGH'
    """)
    blocked_attempts = cursor.fetchone()[0]

    # Use the same value
    threat_alerts = blocked_attempts

    # -------------------------
    # Recent Login Activity
    # -------------------------

    cursor.execute("""
    SELECT
        username,
        ip_address,
        device,
        browser,
        prediction,
        login_time
    FROM login_logs
    ORDER BY id DESC
    LIMIT 10
    """)

    recent_logins = cursor.fetchall()

    conn.close()

    class SimpleUser:
        def __init__(self, name):
            self.username = name

    current_user = SimpleUser(username)
    risk = prediction["risk"] if prediction else "LOW"

    if risk == "HIGH":
        threat_score = 92
        confidence = 97

    elif risk == "MEDIUM":
        threat_score = 60
        confidence = 93

    else:
        threat_score = 22
        confidence = 98

    return render_template(
        "dashboard.html",

        current_user=current_user,

        total_users=total_users,
        today_logins=today_logins,
        blocked_attempts=blocked_attempts,
        threat_alerts=threat_alerts,

        notification_count=7,

        recent_logins=recent_logins,

        threat_level=prediction["risk"] if prediction else "LOW",
        ai_prediction=prediction["prediction"] if prediction else "Normal Login",
        confidence=confidence,
        threat_score=threat_score,
        prediction_reasons=prediction["reasons"] if prediction else ["No suspicious behaviour detected"]
    )
@app.route("/admin")
def admin():

    # User must be logged in
    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    # Only admin can access
    if session["username"] != "admin":
        flash("Access Denied!", "error")
        return redirect(url_for("dashboard"))

    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Total users
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    # Total logins
    cursor.execute("SELECT COUNT(*) FROM login_logs")
    total_logins = cursor.fetchone()[0]

    # High risk logins
    cursor.execute("SELECT COUNT(*) FROM login_logs WHERE risk='HIGH'")
    high_risk = cursor.fetchone()[0]
    # Locked accounts
    cursor.execute("""
    SELECT COUNT(*)
    FROM users
    WHERE account_locked = 1
    """)

    locked_accounts = cursor.fetchone()[0]

    # Registered users
    cursor.execute("""
        SELECT id, username, email, failed_attempts, account_locked
        FROM users
        ORDER BY id DESC
    """)

    users = cursor.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_logins=total_logins,
        high_risk=high_risk,
        locked_accounts=locked_accounts,
        users=users
    )
@app.route("/unlock/<int:user_id>")
def unlock_user(user_id):

    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    UPDATE users
    SET failed_attempts = 0,
        account_locked = 0
    WHERE id = ?
    """, (user_id,))

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

    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            email,
            user_code,
            trusted_device,
            failed_attempts,
            account_locked
        FROM users
        WHERE username=?
    """, (username,))

    user = cursor.fetchone()

    conn.close()

    if not user:
        flash("User account not found.", "error")
        return redirect(url_for("login"))

    return render_template(
        "profile.html",
        user=user
    )

@app.route("/settings")
def settings():

    if "username" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    username = session["username"]

    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            username,
            email
        FROM users
        WHERE username=?
    """, (username,))

    user = cursor.fetchone()

    conn.close()

    if not user:
        flash("User account not found.", "error")
        return redirect(url_for("login"))

    return render_template(
        "settings.html",
        user=user
    )
@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)