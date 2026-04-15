import secrets
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://matt:Savythebird!1@127.0.0.1:3307/database_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secretkey'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

# Google OAuth Config (Replace with your actual credentials)
GOOGLE_CLIENT_ID = '174732562091-gd4mmbm82kluvmsct2iajh2kj1ib68r4.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
oauth = OAuth(app)

# Register Google OAuth
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)


# --- Models ---
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=True)  # Nullable for OAuth users
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Helpers ---
def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    return True, ""


@app.before_request
def handle_session_timeout():
    session.permanent = True  # Refreshes the 5-minute timer on every click


# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user:
            # Check Lockout
            if user.lockout_until and datetime.utcnow() < user.lockout_until:
                flash("Account locked. Please try again in 15 minutes.", "danger")
                return render_template('login.html')

            if bcrypt.check_password_hash(user.password, password):
                user.failed_attempts = 0
                user.lockout_until = None
                db.session.commit()
                login_user(user)
                return redirect(url_for('user_info'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
                    flash("Too many failed attempts. Account locked.", "danger")
                else:
                    flash(f"Invalid password. Attempt {user.failed_attempts}/5", "warning")
                db.session.commit()
        else:
            flash('User not found.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Existing user check
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        # Password strength check
        is_valid, msg = is_password_strong(password)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')


# --- Google OAuth Routes ---
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/login/google/authorize')
def google_authorize():
    token = google.authorize_access_token()
    user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()

    email = user_info['email']
    user = User.query.filter_by(email=email).first()

    if not user:
        # Auto-register OAuth user if they don't exist
        user = User(username=user_info['name'], email=email, password=None)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for('user_info'))


@app.route('/user_info')
@login_required
def user_info():
    return render_template('user_info.html', user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)

# import secrets
# import re
# from flask import Flask, render_template, request, redirect, url_for, flash
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from flask_bcrypt import Bcrypt
# from flask_mail import Mail
#
# app = Flask(__name__)
#
# app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://matt:Savythebird!1@127.0.0.1:3307/database_db"
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SECRET_KEY'] = 'secretkey'
#
# db = SQLAlchemy(app)
# bcrypt = Bcrypt(app)
# login_manager = LoginManager(app)
# login_manager.login_view = 'login'
# mail = Mail(app)
#
# class User(db.Model, UserMixin):
#     __tablename__ = "user"
#
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(50), nullable=False, unique=True)
#     email = db.Column(db.String(120), nullable=False, unique=True)
#     password = db.Column(db.String(255), nullable=False)
#     reset_token = db.Column(db.String(100))
#
# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))
#
# def is_password_strong(password):
#     if len(password) < 8:
#         return False, "Password must be at least 8 characters long."
#     if not any(char.isdigit() for char in password):
#         return False, "Password must contain at least one number."
#     if not any(char.isupper() for char in password):
#         return False, "Password must contain at least one uppercase letter."
#     return True, ""
#
# @app.route('/', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#
#         user = User.query.filter_by(username=username).first()
#
#         if user and bcrypt.check_password_hash(user.password, password):
#             login_user(user)
#             flash("Logged in successfully!", "success")
#             return redirect(url_for('user_info'))
#         else:
#             flash('Invalid username or password', 'danger')
#
#     return render_template('login.html')
#
#
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         email = request.form['email']
#         password = request.form['password']
#
#         if User.query.filter_by(username=username).first():
#             flash('Username already exists.', 'danger')
#             return redirect(url_for('register'))
#
#         if User.query.filter_by(email=email).first():
#             flash('Email already registered.', 'danger')
#             return redirect(url_for('register'))
#
#         # Password validation check
#         is_valid, message = is_password_strong(password)
#         if not is_valid:
#             flash(message, 'danger')
#             return redirect(url_for('register'))
#
#         hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
#         new_user = User(username=username, email=email, password=hashed_pw)
#
#         db.session.add(new_user)
#         db.session.commit()
#
#         flash('Account created successfully!', 'success')
#         return redirect(url_for('login'))
#
#     return render_template('register.html')
#
#
# @app.route('/user_info')
# @login_required
# def user_info():
#     return render_template('user_info.html', user=current_user)
#
#
# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     flash("Logged out successfully!", "success")
#     return redirect(url_for('login'))
#
#
# @app.route('/forgot_password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         new_pw = request.form.get('new_password')
#         confirm_pw = request.form.get('confirm_password')
#
#         user = User.query.filter_by(email=email).first()
#
#         if not user:
#             flash("Email not found!", "danger")
#             return render_template('forgot_pw.html', show_reset=True)
#
#         if not new_pw or not confirm_pw:
#             flash("Please enter and confirm your new password.", "danger")
#             return render_template('forgot_pw.html', show_reset=True, email=email)
#
#         if new_pw != confirm_pw:
#             flash("Passwords do not match!", "danger")
#             return render_template('forgot_pw.html', show_reset=True, email=email)
#
#         # Password validation check for reset
#         is_valid, message = is_password_strong(new_pw)
#         if not is_valid:
#             flash(message, "danger")
#             return render_template('forgot_pw.html', show_reset=True, email=email)
#
#         user.password = bcrypt.generate_password_hash(new_pw).decode('utf-8')
#         db.session.commit()
#
#         flash("Password updated successfully!", "success")
#         return redirect(url_for('login'))
#
#     return render_template('forgot_pw.html', show_reset=False)
#
#
# if __name__ == "__main__":
#     app.run(debug=True)