import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import timedelta

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://matt:Savythebird!1@127.0.0.1:3307/database_db" ## add in your sql server
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(100))

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

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('user_info'))
        else:
            flash('Invalid email or password', 'danger')

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
    # 🔥 THIS IS THE IMPORTANT LINE
    with app.app_context():
        db.create_all()

    app.run(debug=True)