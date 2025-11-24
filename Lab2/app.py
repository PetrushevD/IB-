import base64
import hashlib
import os
import secrets

from flask import Flask, request, render_template, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect

app = Flask(__name__)

# --- Postavki za bezbednost i sesija ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///infosec_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret Key za postpisuvanje na cookies
app.config['SECRET_KEY'] = secrets.token_hex(32)

# HttpOnly atribut za session cookie (Zastita od XSS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)    # 64 karakteri za SHA256
    salt = db.Column(db.String(24), nullable=False)

with app.app_context():
    db.create_all()


# --- Pomosni funkcii za bezbednost ---
def generate_salt():
    return base64.b64encode(os.urandom(16)).decode('utf-8')

# heshiranje so SHA-256
def hash_password(password, salt):
    salted_password = (password + salt).encode('utf-8')
    return hashlib.sha256(salted_password).hexdigest()

# --- 1.REGISTRATION ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            return render_template('register.html', error="Email already registered")

        salt = generate_salt()

        hashed_password = hash_password(password, salt)

        new_user = User(email=email, password_hash=hashed_password, salt=salt)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login', success=True))

    return render_template('register.html')

# --- 2.LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user:
            return render_template('login.html', error="Invalid credentials")

        provided_hash = hash_password(password, user.salt)

        if provided_hash == user.password_hash:
            session.clear()
            session['user_id'] = user.id

            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

# --- 3.Profile ---
@app.route('/profile')
def profile():
    # Access Control
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

# --- 4.Logout ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login', logout=True))

if __name__ == '__main__':
    app.run(debug=True)
