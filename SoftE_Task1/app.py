import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash

app = Flask(__name__)

# ---------------- CONFIG ----------------
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://matt:Savythebird!1@127.0.0.1:3307/database_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secretkey'

# Email config (CHANGE THESE)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'

# ---------------- EXTENSIONS ----------------
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# ---------------- MODEL ----------------
class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(100))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ----------------

# LOGIN
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user:
            try:
                if bcrypt.check_password_hash(user.password, password):
                    login_user(user)
                    # Store session info
                    session['user_id'] = user.id
                    session['username'] = user.username
                    flash("Logged in successfully!", "success")
                    return redirect(url_for('user_info'))
                else:
                    flash('Invalid username or password', 'danger')
            except ValueError:
                flash('Password hash invalid. Please reset your password.', 'danger')
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# USER PAGE
@app.route('/user_info')
@login_required
def user_info():
    # Use session info to display
    username = session.get('username', current_user.username)
    return render_template('user_info.html', username=username)


# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()  # Clear session info
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))


# ---------------- PASSWORD RESET (Combined) ----------------
@app.route('/forgot_pw', methods=['GET', 'POST'])
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

        # Hash and update the password
        hashed_pw = bcrypt.generate_password_hash(new_pw).decode('utf-8')
        user.password = hashed_pw
        db.session.commit()
        flash("Password updated successfully!", "success")
        return redirect(url_for('login'))

    # GET request shows initial email input
    return render_template('forgot_pw.html', show_reset=False)


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
