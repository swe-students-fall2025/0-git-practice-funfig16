import os
import smtplib
from email.message import EmailMessage
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session
)
from pymongo import MongoClient, errors
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv

# -------------------
# Config
# -------------------
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "auth_demo_db")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

# Optional SMTP for real emails (otherwise we print the link in console)
MAIL_FROM = os.getenv("MAIL_FROM")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

# Mongo
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users = db.users

# Ensure email uniqueness
try:
    users.create_index("email", unique=True)
except errors.OperationFailure:
    pass

# Token serializer for password reset
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="password-reset-salt")

# -------------------
# Helpers
# -------------------

def current_user():
    if "user_email" in session:
        return users.find_one({"email": session["user_email"]})
    return None


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please sign in first.")
            return redirect(url_for("signin"))
        return view(*args, **kwargs)
    return wrapped


def send_reset_email(to_email: str, token: str):
    reset_link = url_for("reset_password", token=token, _external=True)
    subject = "Password Reset"
    body = f"Click this link to reset your password: {reset_link}\n(This link expires in 60 minutes.)"

    # If SMTP is configured, send a real email; otherwise print to console
    if SMTP_HOST and MAIL_FROM:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = MAIL_FROM
        msg["To"] = to_email
        msg.set_content(body)
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls()
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        except Exception as e:
            print("[EMAIL ERROR]", e)
            print("[FALLBACK] Reset link:", reset_link)
    else:
        print("\n=== Password reset link (console mode) ===")
        print(reset_link)
        print("=======================================\n")

# -------------------
# Routes
# -------------------

@app.route("/")
@login_required
def index():
    user = current_user()
    return render_template("base.html", title="Home", content=f"Welcome, {user['email']}!")


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = users.find_one({"email": email})
        if user and check_password_hash(user["password_hash"], password):
            session["user_email"] = email
            flash("Logged in successfully.")
            return redirect(url_for("index"))
        flash("Invalid email or password.")
    return render_template("signin.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or not password:
            flash("Email and password are required.")
            return render_template("signup.html")
        if password != confirm:
            flash("Passwords do not match.")
            return render_template("signup.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return render_template("signup.html")
        try:
            users.insert_one({
                "email": email,
                "password_hash": generate_password_hash(password),
                "created_at": datetime.utcnow(),
            })
            flash("Account created! Please sign in.")
            return redirect(url_for("signin"))
        except errors.DuplicateKeyError:
            flash("Email already registered. Please sign in.")
            return redirect(url_for("signin"))
    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You are logged out.")
    return redirect(url_for("signin"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = users.find_one({"email": email})
        # not reveal whether the email exists for privacy
        if user:
            token = serializer.dumps(email)
            send_reset_email(email, token)
        flash("If that email is registered, a recovery link has been sent.")
        return redirect(url_for("signin"))
    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, max_age=3600)  # 1 hour
    except SignatureExpired:
        flash("The reset link has expired. Please submit a new request.")
        return redirect(url_for("forgot"))
    except BadSignature:
        flash("Invalid reset link.")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if password != confirm:
            flash("Passwords do not match.")
            return render_template("reset.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return render_template("reset.html")
        users.update_one({"email": email}, {"$set": {"password_hash": generate_password_hash(password)}})
        flash("Your password has been reset. Please sign in.")
        return redirect(url_for("signin"))

    return render_template("reset.html")


if __name__ == "__main__":
    app.run(debug=True)
