import secrets
from datetime import timedelta, datetime

from flask import Flask, request, render_template, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Postavki za bezbednost i sesija ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///infosec_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret Key za postpisuvanje na cookies
app.config['SECRET_KEY'] = secrets.token_hex(32)

# HttpOnly atribut za session cookie (Zastita od XSS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.app_context().push()
app.config['SESSION_COOKIE_SECURE'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    is_active = db.Column(db.Boolean, default=False)    # Dali e verificiran
    verification_token = db.Column(db.String(64), unique=True, nullable=True)   # Verification token

    current_2fa_code = db.Column(db.String(6), nullable=True)   # 6 digit code
    two_fa_expiry = db.Column(db.DateTime, nullable=True)   # When the code expires

# Kreirame nova tabela Session za da gi zacuvame site aktivni sesii na serverskata strana
class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False) # Unikaten token (Session ID)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creation_time = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_time = db.Column(db.DateTime, nullable=False)
    #Povrzuvanje na sesijata so korisnikot
    user = db.relationship('User', backref=db.backref('sessions', lazy=True))

with app.app_context():
    db.create_all()


# --- Pomosni funkcii za upravuvanje so sesii ---
def create_server_session(user_id):
    #1.Generiranje na bezbeden Session ID
    session_token = secrets.token_urlsafe(32)

    #2.Postavuvanje vreme na istekuvanje (primer 30 minuti)
    expiry = datetime.utcnow() + timedelta(minutes=30)

    #3.Kreiranje nov zapis vo bazata
    new_session = Session(
        session_id=session_token,
        user_id=user_id,
        expiry_time=expiry
    )
    db.session.add(new_session)
    db.session.commit()

    return session_token


def delete_server_session(session_token):
    #Brisenje na sesijata od bazata
    Session.query.filter_by(session_id=session_token).delete()
    db.session.commit()


# --- Pomosna funkcija za proverka na tekovnata sesija ---
def get_current_user_from_session():
    # 1.Zemanje na tokenot od cookie
    session_token = request.cookies.get('session_id')

    if not session_token:
        return None

    # 2.Baranje na sesijata vo bazata
    current_session = Session.query.filter_by(session_id=session_token).first()

    # 3.Validacija na sesijata
    if current_session and current_session.expiry_time > datetime.utcnow():
        # Dokolku e validna, vrati go korisnikot
        return current_session.user
    else:
        # Sesijata ne e pronajdena ili istekla - izbrisi go cookie-to
        return None


# --- 1.REGISTRATION 2fa ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            return render_template('register.html', error="Email already registered")

        hashed_password = generate_password_hash(password)

        token = secrets.token_urlsafe(32)   # Generira 32 bajti bezbeden, URL token

        new_user = User(
            email=email,
            password_hash=hashed_password,
            is_active=False,    # Korisnikot e neaktiven do verifikacija
            verification_token=token
        )

        db.session.add(new_user)
        db.session.commit()

        # Simulacija na isprakjanje email so link
        verification_link = url_for('verify_email', token=token, _external=True)

        print(f"--- EMAIL SIMULATION ---")
        print(f"Send this link to {email}: {verification_link}")
        print(f"--- END OF SIMULATION ---")

        return render_template('register.html', success="Registration successful. Check your email to activate your account")

    return render_template('register.html')

# --- 1.1 EMAIL Verification ---
@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()

    if user:
        # Ako tokenot e pronajden, aktiviraj go korisnikot
        user.is_active = True
        user.verification_token = None  # Otstrani go tokenot za da ne moze da se koristi povtorno
        db.session.commit()

        return redirect(url_for('login', message="Account successfully activated. Proceed to login"))
    else:
        # Ako tokenot ne postoi ili e vekje iskoristen
        return "Invalid token verification", 404

# --- 2.LOGIN (Faza 1: Proverka na lozinka) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            return render_template('login.html', error="Invalid credentials")

        if not user.is_active:
            return render_template('login.html', error="Your account is not activated. Check your email")

        # Lozinkata e tocna - zapocnuva 2FA procesot

        # 1.Generiranje na 6-cifren kod (OTP)
        # secrets.randbelow(1000000) dava broj od 0 do 999999
        two_fa_code = str(secrets.randbelow(1000000)).zfill(6)

        # 2.Postavuvanje na istekuvanje (primer 3 minuti)
        expiry_time = datetime.utcnow() + timedelta(minutes=3)

        # 3.Zacuvuvanje na kodot i istekot vo bazata
        user.current_2fa_code = two_fa_code
        user.two_fa_expiry = expiry_time
        db.session.commit()

        # 4.Simulacija na isprakjanje email/SMS
        print(f"--- 2FA SIMULATION ---")
        print(f"Send this code to {user.email}: {two_fa_code} (Expires in {expiry_time.strftime('%H:%M:%S')}")
        print(f"--- END OF SIMULATION ---")

        # 5.Privremeno cuvanje na ID-to vo sesijata za 2FA
        # Koristime 'temp_user_id' za da pokazeme deka korisnikot e samo POTVRDEN, ne i NAJAVEN
        session['temp_user_id'] = user.id

        return redirect(url_for('two_factor_auth'))
    return render_template('login.html')

# --- 2.1 TWO FACTOR AUTH (Faza 2: Proverka na kod) ---
@app.route('/2fa', methods=['GET', 'POST'])
def two_factor_auth():
    #Security check: mora da pominat niz Faza 1
    if 'temp_user_id' not in session:
        return redirect(url_for('login', error="Please login again"))

    user = User.query.get(session['temp_user_id'])

    if user.two_fa_expiry and user.two_fa_expiry < datetime.utcnow():
        # Clean up the expired code
        user.current_2fa_code = None
        user.two_fa_expiry = None
        db.session.commit()
        session.pop('temp_user_id', None)
        return redirect(url_for('login', error="2FA code expired before submission. Please login again"))

    if request.method == 'POST':
        submitted_code = request.form['two_fa_code']

        # 1.Proverka dali kodot e tocen I dali ne e istecen
        if user.current_2fa_code == submitted_code and user.two_fa_expiry > datetime.utcnow():

            # 1.Generiranje Sesija i token
            session_token = create_server_session(user.id)

            # 2.Brisenje na FLASK SESSION
            session.clear()     # Gi briseme site stari Flask cookies (vklucitelno i temp_user_id)

            # 3.Kreiranje na Response objekt za postavuvanje na cookie
            response = redirect(url_for('profile'))

            # 4.Postavuvanje na SESSION ID KAKO HTTP-ONLY COOKIE
            response.set_cookie(
                'session_id',           #Ime na cookie
                session_token,              #Vrednost (Session ID)
                httponly=True,
                secure=app.config['SESSION_COOKIE_SECURE'],
                samesite='Lax'
            )
            return response
        else:
            return render_template('2fa.html', error="Invalid or expired 2FA code")

    return render_template('2fa.html')

# --- 3.Profile ---
@app.route('/profile')
def profile():
    user = get_current_user_from_session()

    if not user:
        # Kje morame da go ispratime i Response objektot za da go izbriseme istecenoto cookie
        response = redirect(url_for('login', error="Session expired or invalid. Please login"))
        response.delete_cookie('session_id')
        return response

    return render_template('profile.html', user=user)

# --- 4.Logout ---
#Odjavuvanjeto sega znaci brisenje na sesijata i brisenje na cookie-to
@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_id')

    if session_token:
        delete_server_session(session_token)    #Brisenje od bazata

    #Brisenje na site Flask Session podatoci (za sekoj slucaj)
    session.clear()

    #Kreiranje Response za brisenje na cookie-to od strana na klientot
    response = redirect(url_for('login', logout=True))
    response.delete_cookie('session_id')    #Brisenje na cookie-to
    return response

if __name__ == '__main__':
    app.run(debug=True)
