# OVA E KAKO app.py SAMO SE KORISTI RACNO HESHIRANJE CISTO ZA SPOREDBA I UCENJE
# PRAVILNIOT KOD E app.py

import hashlib

from flask import Flask, render_template, request, url_for, session
from werkzeug.utils import redirect

testtest = Flask(__name__)
testtest.secret_key = 'supersecretkey'

# primer baza na korisnici
users = {}

@testtest.route('/')
def index():
    return render_template('index.html')

@testtest.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # heshiranje bez salt
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        users[username] = hashed_password

        return redirect(url_for('login'))
    return render_template('register.html')

@testtest.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if username in users and users[username] == hashed_password:
            session['username'] = username
            return f"Hello, {username}! You are logged in."
        else:
            return "Invalid credentials!"
    return render_template('login.html')

@testtest.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    testtest.run(debug=True)