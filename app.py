from flask import Flask, render_template, request, redirect, url_for, flash, session
from prediction.predict import predict_login
from datetime import datetime
import random

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

            session["username"] = username

            flash(f"Account created successfully! Welcome, {username}.", "success")

            return redirect(url_for("dashboard"))

        flash("Please fill in all required fields.", "error")

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():

    username = session.get("username", "Admin")
    prediction = session.get("prediction")

    # Demo login history
    demo_logins = [
        {
            "username": "admin",
            "ip_address": "192.168.1.1",
            "device": "Desktop",
            "browser": "Chrome",
            "status": "success",
            "timestamp": "2 min ago",
        },
        {
            "username": "keerthi",
            "ip_address": "203.45.67.89",
            "device": "Mobile",
            "browser": "Safari",
            "status": "success",
            "timestamp": "5 min ago",
        },
        {
            "username": "user_003",
            "ip_address": "185.220.101.4",
            "device": "Laptop",
            "browser": "Firefox",
            "status": "failed",
            "timestamp": "8 min ago",
        },
        {
            "username": "analyst1",
            "ip_address": "10.0.0.25",
            "device": "Desktop",
            "browser": "Edge",
            "status": "success",
            "timestamp": "12 min ago",
        },
        {
            "username": "unknown",
            "ip_address": "45.142.212.55",
            "device": "Unknown",
            "browser": "Unknown",
            "status": "failed",
            "timestamp": "15 min ago",
        },
    ]

    class SimpleUser:
        def __init__(self, name):
            self.username = name

    current_user = SimpleUser(username)
    return render_template(
    "dashboard.html",

    current_user=current_user,

    total_users=1247,
    today_logins=342,
    blocked_attempts=89,
    threat_alerts=12,
    notification_count=7,

    threat_level=prediction["risk"] if prediction else "LOW",

    ai_prediction=prediction["prediction"] if prediction else "Normal Login",

    confidence=95 if prediction and prediction["risk"] == "HIGH" else 97,

    prediction_reasons=prediction["reasons"] if prediction else ["No suspicious behaviour detected"],

    recent_logins=demo_logins,
)


@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)