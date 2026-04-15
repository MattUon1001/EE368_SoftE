import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta

import requests
from requests_oauthlib import OAuth2Session
from datetime import timedelta
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://matt:Savythebird!1@127.0.0.1:3307/database_db" ## add in your sql server
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secretkey'

CLIENT_ID = "Ov23lidJKUGvzNAx3QDA"
CLIENT_SECRET = "984b699a2b127fbd43dba78379bc0b524fdd3beb"
AUTH_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"
REDIRECT_URI = "http://127.0.0.1:5000/github/callback"

GOOGLE_CLIENT_ID = "414249642510-6g7gefars788r1n5b4tv7p5bf3q2v5v2.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USER_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000/google/callback"


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# --- Lockout configuration ---
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

# In-memory store: { username: {"count": int, "locked_until": datetime or None} }
failed_attempts = {}

class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(100))



def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    return True, ""


def is_account_locked(username):
    """Returns (is_locked: bool, seconds_remaining: int)."""
    record = failed_attempts.get(username)
    if not record:
        return False, 0

    locked_until = record.get("locked_until")
    if locked_until and datetime.now() < locked_until:
        remaining = int((locked_until - datetime.now()).total_seconds())
        return True, remaining

    # Lockout has expired — clear it
    if locked_until and datetime.now() >= locked_until:
        failed_attempts.pop(username, None)

    return False, 0


def record_failed_attempt(username):
    """Increment failed attempt counter; lock account if threshold is reached."""
    record = failed_attempts.setdefault(username, {"count": 0, "locked_until": None})
    record["count"] += 1

    if record["count"] >= MAX_FAILED_ATTEMPTS:
        record["locked_until"] = datetime.now() + LOCKOUT_DURATION


def reset_failed_attempts(username):
    """Clear the failed attempt record on successful login."""
    failed_attempts.pop(username, None)

def split_name(full_name):
    if not full_name:
        return "", ""
    parts = full_name.strip().split(" ", 1)
    fname = parts[0]
    lname = parts[1] if len(parts) > 1 else ""
    return fname, lname

@app.route("/google/login")
def google_login():
    google = OAuth2Session(
        GOOGLE_CLIENT_ID,
        redirect_uri=GOOGLE_REDIRECT_URI,
        scope="openid email profile"
    )

    auth_url, state = google.authorization_url(GOOGLE_AUTH_URL)
    session["google_oauth_state"] = state

    return redirect(auth_url)
@app.route("/google/callback")
def google_callback():
    google = OAuth2Session(
        GOOGLE_CLIENT_ID,
        state=session.get("google_oauth_state"),
        redirect_uri=GOOGLE_REDIRECT_URI
    )

    google.fetch_token(
        GOOGLE_TOKEN_URL,
        client_secret=GOOGLE_CLIENT_SECRET,
        authorization_response=request.url
    )

    user_info = google.get(GOOGLE_USER_URL).json()
    google_email = user_info["email"]

    user = User.query.filter_by(email=google_email).first()

    if not user:
        user = User(
            fname=user_info.get("name") or "GoogleUser",
            lname="Google",
            email=google_email,
            password=bcrypt.generate_password_hash(secrets.token_hex(16)).decode("utf-8")
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)

    return redirect(url_for("user_info"))
@app.route("/github/login")
def github_login():
    github = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI)
    auth_url, state = github.authorization_url(AUTH_URL)
    session["oauth_state"] = state
    return redirect(auth_url)
@app.route("/github/callback")
def github_callback():
    github = OAuth2Session(CLIENT_ID, state=session["oauth_state"])

    github.fetch_token(
        TOKEN_URL,
        client_secret=CLIENT_SECRET,
        authorization_response=request.url
    )

    user_info = github.get(USER_URL).json()

    github_email = user_info["login"] + "@github.com"

    # check if user exists
    user = User.query.filter_by(email=github_email).first()

    # create user if not exists
    if not user:
        user = User(
            fname=user_info.get("name") or user_info["login"],
            lname="GitHub",
            email=github_email,
            password=bcrypt.generate_password_hash(secrets.token_hex(16)).decode("utf-8")
        )
        db.session.add(user)
        db.session.commit()

    # THIS is the important part
    login_user(user)

    return redirect(url_for("user_info"))

@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return f"Welcome {session['user']}"
    return redirect("/")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    return True, ""

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']


        locked, seconds_left = is_account_locked(email)
        if locked:
            minutes = seconds_left // 60
            seconds = seconds_left % 60
            flash(
                f"Account is locked due to too many failed attempts. "
                f"Try again in {minutes}m {seconds}s.",
                "danger"
            )
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()


        if user and bcrypt.check_password_hash(user.password, password):
            reset_failed_attempts(email)
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('user_info'))


        else:
            record_failed_attempt(email)

            record = failed_attempts.get(email, {})
            attempts_so_far = record.get("count", 0)

            if attempts_so_far >= MAX_FAILED_ATTEMPTS:
                flash(
                    f"Too many failed attempts. Your account has been locked for "
                    f"{int(LOCKOUT_DURATION.total_seconds() // 60)} minutes.",
                    "danger"
                )
            else:
                remaining_attempts = MAX_FAILED_ATTEMPTS - attempts_so_far
                flash(
                    f"Invalid email or password. "
                    f"{remaining_attempts} attempt(s) remaining before lockout.",
                    "danger"
                )

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        is_valid, message = is_password_strong(password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(fname=fname, lname=lname, email=email, password=hashed_pw)

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/user_info')
@login_required
def user_info():
    return render_template('user_info.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        new_pw = request.form.get('new_password')
        confirm_pw = request.form.get('confirm_password')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email not found!", "danger")
            return render_template('forgot_pw.html', show_reset=True)

        if not new_pw or not confirm_pw:
            flash("Please enter and confirm your new password.", "danger")
            return render_template('forgot_pw.html', show_reset=True, email=email)

        if new_pw != confirm_pw:
            flash("Passwords do not match!", "danger")
            return render_template('forgot_pw.html', show_reset=True, email=email)

        is_valid, message = is_password_strong(new_pw)
        if not is_valid:
            flash(message, "danger")
            return render_template('forgot_pw.html', show_reset=True, email=email)

        user.password = bcrypt.generate_password_hash(new_pw).decode('utf-8')
        db.session.commit()

        flash("Password updated successfully!", "success")
        return redirect(url_for('login'))

    return render_template('forgot_pw.html', show_reset=False)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
