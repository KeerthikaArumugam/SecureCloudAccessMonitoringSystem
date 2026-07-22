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

        if username and password:

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
            # (Later these will come from the database)
            user_id = random.randint(0, 800)
            pc_id = random.randint(0, 700)
            activity = 1

            # AI Prediction
            prediction = predict_login(
                user=user_id,
                pc=pc_id,
                activity=activity,
                hour=hour,
                day=day,
                month=month,
                weekday=weekday
            )

            # Connect to database
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

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

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if username and email and password:
            import sqlite3

            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO users (username, email, password)
            VALUES (?, ?, ?)
            """, (
                username,
                email,
                password
            ))

            conn.commit()
            conn.close()

            session["username"] = username

            flash(f"Account created successfully! Welcome, {username}.", "success")

            return redirect(url_for("dashboard"))

        flash("Please fill in all required fields.", "error")

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():

    username = session.get("username", "Admin")
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
        confidence=95 if prediction and prediction["risk"] == "HIGH" else 97,
        prediction_reasons=prediction["reasons"] if prediction else ["No suspicious behaviour detected"]
    )

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)