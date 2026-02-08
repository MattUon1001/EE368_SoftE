from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


# Database Setup for User Info [cite: 13-17]
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


with app.app_context():
    db.create_all()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        # TASK 7: Check if email exists [cite: 45]
        if User.query.filter_by(email=email).first():
            flash('Existing users trying to register with the same email.')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(request.form.get('password'))
        new_user = User(
            first_name=request.form.get('f_name'),
            last_name=request.form.get('l_name'),
            email=email,
            password=hashed_pw
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        # TASK 7: Handle invalid credentials [cite: 44]
        if user and check_password_hash(user.password, request.form.get('password')):
            session['user_id'] = user.id
            return redirect(url_for('user_info'))
        flash('Invalid email or password.')
    return render_template('login.html')


# TASK 6: User Info Page [cite: 36-40]
@app.route('/user_info')
def user_info():
    # Access Control: Redirect if not logged in [cite: 41-42]
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('user_info.html', user=user)


# TASK 7: General system error handling [cite: 46]
@app.errorhandler(500)
def internal_error(error):
    return "A system error occurred. Please check your database connection.", 500


if __name__ == '__main__':
    app.run(debug=True)