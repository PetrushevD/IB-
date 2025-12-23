import re
import secrets
from datetime import timedelta, datetime
from functools import wraps

from flask import Flask, request, render_template, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import backref
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

    is_active = db.Column(db.Boolean, default=False)  # Dali e verificiran
    verification_token = db.Column(db.String(64), unique=True, nullable=True)  # Verification token

    current_2fa_code = db.Column(db.String(6), nullable=True)  # 6 digit code
    two_fa_expiry = db.Column(db.DateTime, nullable=True)  # When the code expires

    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)  # Dodavame FK kon Role
    role = db.relationship('Role', backref=db.backref('users', lazy=True))  # Postavuvanje na vrska do Role modelot

    jit_role_expiry = db.Column(db.DateTime, nullable=True)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)  # Unikaten token (Session ID)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creation_time = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_time = db.Column(db.DateTime, nullable=False)
    user = db.relationship('User', backref=db.backref('sessions', lazy=True))


# Association Table za N:N vrska pomegu Role i Permission
class RolePermission(db.Model):
    __tablename__ = 'role_permission'
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'), primary_key=True)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))

    # N:N vrska so Permission preku RolePermission
    permissions = db.relationship('Permission', secondary='role_permission',
                                  backref=db.backref('roles', lazy='dynamic'))

    # Dodavame hierarhija (za baranjeto "organizaciski ulogi so hierarhija")
    parent_role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)
    parent = db.relationship('Role', remote_side=[id], backref='children')


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)  # Pr. 'create_post', 'delete_user'
    description = db.Column(db.String(255))


class ResourceAccess(db.Model):
    __tablename__ = 'resource_access'

    id = db.Column(db.Integer, primary_key=True)
    # 1. Koj korisnik go ima pristapot
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # 2. Na koj resurs se odnesuva
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.Integer, nullable=False)
    # 3. Kakva privilegija ima
    permission_type = db.Column(db.String(50), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=True)
    user = db.relationship('User', backref=db.backref('resource_accesses', lazy='dynamic'))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'resource_type', 'resource_id', 'permission_type',
                            name = 'uq_user_resource_permission'),
    )

with app.app_context():
    db.create_all()


def initialize_roles_and_permissions():
    # 1. Kreiranje na dozvoli
    permissions_list = [
        'view_dashboard', 'create_post', 'edit_post', 'delete_post',
        'manage_users', 'view_reports', 'super_admin_access'
    ]
    for p_name in permissions_list:
        if not Permission.query.filter_by(name=p_name).first():
            db.session.add(Permission(name=p_name, description=f'Permission to {p_name.replace("_", " ")}'))

    db.session.commit()

    # Zemanje na kreiranite dozvoli za povrzuvanje
    view_dashboard = Permission.query.filter_by(name='view_dashboard').first()
    create_post = Permission.query.filter_by(name='create_post').first()
    edit_post = Permission.query.filter_by(name='edit_post').first()
    manage_users = Permission.query.filter_by(name='manage_users').first()
    super_admin_access = Permission.query.filter_by(name='super_admin_access').first()

    # 2. Kreiranje na Ulogi (Roles) so hierarhija i dozvoli
    if not Role.query.filter_by(name='SuperAdmin').first():
        super_admin = Role(name='SuperAdmin', description='Global access to everything')
        super_admin.permissions = Permission.query.all()  # Gi dobiva site dozvoli
        db.session.add(super_admin)
        db.session.commit()  # Commit megju kreiranjeto na roditelskata uloga i decata

    super_admin = Role.query.filter_by(name='SuperAdmin').first()  # Povtorno zemanje po commit

    # Organizational Roles (Hierarhija)
    if not Role.query.filter_by(name='Manager').first():
        manager = Role(name='Manager', description='Organizational Manager',
                       parent_role_id=super_admin.id if super_admin else None)
        manager.permissions.extend([view_dashboard, create_post, edit_post, manage_users])
        db.session.add(manager)

    if not Role.query.filter_by(name='Editor').first():
        editor = Role(name='Editor', description='Content Editor')
        editor.permissions.extend([view_dashboard, create_post, edit_post])
        db.session.add(editor)

    if not Role.query.filter_by(name='Reader').first():
        reader = Role(name='Reader', description='View-only access')
        reader.permissions.append(view_dashboard)
        db.session.add(reader)

    db.session.commit()


def has_resource_permission(user, resource_type, resource_id, permission_type):
    if not user:
        return False

    if user.role and user.role.name == 'SuperAdmin':
        return True

    # Proverka vo ReBAC tabelata
    access = ResourceAccess.query.filter_by(
        user_id=user.id,
        resource_type=resource_type,
        resource_id=resource_id,
        permission_type=permission_type
    ).first()

    if access:
        if access.expiry_time and access.expiry_time < datetime.utcnow():
            db.session.delete(access)
            db.session.commit()
            return False
        return True
    return False


def grant_resource_permission(user_id, resource_type, resource_id, permission_type):
    existing = ResourceAccess.query.filter_by(
        user_id=user_id, resource_type=resource_type,
        resource_id=resource_id, permission_type=permission_type
    ).first()

    if not existing:
        new_access = ResourceAccess(
            user_id=user_id, resource_type=resource_type,
            resource_id=resource_id, permission_type=permission_type
        )
        db.session.add(new_access)
        db.session.commit()
        return True
    return False

# --- Povikaj ja funkcijata na startanje na aplikacijata ---
with app.app_context():
    db.create_all()

    initialize_roles_and_permissions()


def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number"
    return None


def create_server_session(user_id):
    session_token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(minutes=30)
    new_session = Session(
        session_id=session_token,
        user_id=user_id,
        expiry_time=expiry
    )
    db.session.add(new_session)
    db.session.commit()

    return session_token


def delete_server_session(session_token):
    Session.query.filter_by(session_id=session_token).delete()
    db.session.commit()


# --- Pomosna funkcija za proverka na tekovnata sesija ---
def get_current_user_from_session():
    session_token = request.cookies.get('session_id')

    if not session_token:
        return None

    current_session = Session.query.filter_by(session_id=session_token).first()

    if current_session and current_session.expiry_time > datetime.utcnow():
        return current_session.user
    else:
        return None


# --- Pomosna funkcija za kontrola na pristap bazirana na Role/Permission ---
def permission_required(permission_name):
    """
    Dekorator koj proveruva dali tekovniot korisnik ja ima baranata dozvola
    (permission_name) pred da dozvoli pristap do rutata.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user_from_session()
            # 1. Proverka na avtentikacija
            if not user:
                # Ako ne e logiran, isprati go na login
                response = redirect(url_for('login', error="Authorization required. Please log in."))
                # Za sekoj slucaj, izbrisi go eventualnoto nevalidno cookie
                response.delete_cookie('session_id')
                return response

            # JIT logika: Proverka na istek na privremena uloga
            if user.jit_role_expiry and user.jit_role_expiry < datetime.utcnow():
                # Ako istekol JIT pristapot, otstrani go istekot od bazata
                user.jit_role_expiry = None
                db.session.commit()

            # 2. Proverka na avtorizacija
            # Dali korisnikot ima role?
            if not user.role:
                return "Forbidden (403): User has no role assigned", 403

            # Dali ulogata na korisnikot ja sodrzi baranata dozvola (permission)?
            # So `any()` se proveruva efikasno vo listata na dozvoli povrzani so ulogata
            has_permission = any(p.name == permission_name for p in user.role.permissions)

            if not has_permission:
                # Odbien pristap
                return render_template(
                    'forbidden.html',
                    error=f"You do not have the required permission: '{permission_name}'",
                    user=user
                ), 403
            # Pristap dozvolen
            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            return render_template('register.html', error="Email already registered")

        validation_error = validate_password(password)
        if validation_error:
            return render_template('register.html', error=validation_error)

        # --- RBAC: Avtomatsko dodeluvanje SuperAdmin na PRV korisnik ---

        if not User.query.first():
            # Ako e PRV korisnik vo sistemot, dodeli mu SuperAdmin uloga
            default_role = Role.query.filter_by(name='SuperAdmin').first()
        else:
            # Ako NE e prv, dodeli mu standardna Reader uloga
            default_role = Role.query.filter_by(name='Reader').first()

        if not default_role:
            return render_template('register.html', error="System error: Default role not found")
        # ---------------------------------------------------

        hashed_password = generate_password_hash(password)
        token = secrets.token_urlsafe(32)

        new_user = User(
            email=email,
            password_hash=hashed_password,
            is_active=False,
            verification_token=token,
            role_id=default_role.id
        )

        db.session.add(new_user)
        db.session.commit()
        verification_link = url_for('verify_email', token=token, _external=True)

        print(f"--- EMAIL SIMULATION ---")
        print(f"Send this link to {email}: {verification_link}")
        print(f"--- END OF SIMULATION ---")

        return render_template('register.html',
                               success="Registration successful. Check your email to activate your account")

    return render_template('register.html')


# --- 1.1 EMAIL Verification ---
@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()

    if user:
        user.is_active = True
        user.verification_token = None
        db.session.commit()

        return redirect(url_for('login', message="Account successfully activated. Proceed to login"))
    else:
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

        two_fa_code = str(secrets.randbelow(1000000)).zfill(6)

        expiry_time = datetime.utcnow() + timedelta(minutes=3)

        user.current_2fa_code = two_fa_code
        user.two_fa_expiry = expiry_time
        db.session.commit()

        print(f"--- 2FA SIMULATION ---")
        print(f"Send this code to {user.email}: {two_fa_code} (Expires in {expiry_time.strftime('%H:%M:%S')}")
        print(f"--- END OF SIMULATION ---")

        session['temp_user_id'] = user.id

        return redirect(url_for('two_factor_auth'))
    return render_template('login.html')


# --- 2.1 TWO FACTOR AUTH (Faza 2: Proverka na kod) ---
@app.route('/2fa', methods=['GET', 'POST'])
def two_factor_auth():
    if 'temp_user_id' not in session:
        return redirect(url_for('login', error="Please login again"))

    user = User.query.get(session['temp_user_id'])

    if user.two_fa_expiry and user.two_fa_expiry < datetime.utcnow():
        user.current_2fa_code = None
        user.two_fa_expiry = None
        db.session.commit()
        session.pop('temp_user_id', None)
        return redirect(url_for('login', error="2FA code expired before submission. Please login again"))

    if request.method == 'POST':
        submitted_code = request.form['two_fa_code']

        if user.current_2fa_code == submitted_code and user.two_fa_expiry > datetime.utcnow():

            session_token = create_server_session(user.id)

            session.clear()

            response = redirect(url_for('profile'))

            response.set_cookie(
                'session_id',
                session_token,
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
        response = redirect(url_for('login', error="Session expired or invalid. Please login"))
        response.delete_cookie('session_id')
        return response

    # Obezbeduva deka site ulogi i dozvoli se ucitani pri renderiranje
    # Ako korisnikot e SuperAdmin, ova nema da bide problem.
    return render_template('profile.html', user=user)


# --- 3.1 Zastitena (Protected) Ruta za Admini/Editori ---
@app.route('/create_content', methods=['GET', 'POST'])
@permission_required('create_post')
def create_content():
    user = get_current_user_from_session()

    if request.method == 'POST':
        # Simulacija na kreiranje sodrzina
        return render_template('protected.html', user=user, message="Content successfully created!")
    return render_template('protected.html', user=user, message="You can access the content creation page.")


# --- 3.2 Zastitena (Protected) Ruta za SuperAdmini ---
@app.route('/manage_system')
@permission_required('super_admin_access')
def manage_system():
    user = get_current_user_from_session()
    return render_template('protected.html', user=user, message="Welcome to the Super Admin System Management Panel!")


# --- 4. Administration Management (za testiranje) ---
@app.route('/admin/set_role/<int:user_id>', methods=['GET', 'POST'])
@permission_required('manage_users')  # Samo korisnici so ovaa dozvola moze da pristapat
def set_user_role(user_id):
    current_user = get_current_user_from_session()
    if not current_user:
        return redirect(url_for('login'))

    user_to_change = User.query.get_or_404(user_id)
    all_roles = Role.query.all()

    if request.method == 'POST':
        new_role_id = request.form.get('role_id')
        new_role = Role.query.get(new_role_id)

        if new_role:
            user_to_change.role = new_role
            db.session.commit()
            return redirect(url_for('set_user_role', user_id=user_id,
                                    success=f"Successfully set role for {user_to_change.email} to {new_role.name}"))
        else:
            return render_template('set_role.html', user=current_user, user_to_change=user_to_change, roles=all_roles,
                                   error="Invalid role selected")

    # Listanje na site korisnici i nivnite ulogi
    all_users = User.query.all()

    return render_template('set_role.html', user=current_user, all_users=all_users, roles=all_roles,
                           user_to_change=user_to_change)


@app.route('/request_jit_manager')
@permission_required('view_dashboard') # Samo Editori i Manageri mozat da pobaraat
def request_jit_manager():
    user = get_current_user_from_session()

    # Se dobiva Manager uloga, cija navisoka dozvola e 'manage_users'
    manager_role = Role.query.filter_by(name='Manager').first()

    if not manager_role:
        return "System Error: Manager role not found", 500

    user.jit_role_expiry = datetime.utcnow() + timedelta(minutes=5)
    user.role_id = manager_role.id
    user.role = manager_role
    db.session.commit()

    return redirect(url_for('profile', success=f"JIT Manager Access Granted!"))


# Dodaj lista na korisnici za da moze da se pristapi do poedinecniot link
@app.route('/admin/users_list')
@permission_required('manage_users')
def users_list():
    all_users = User.query.all()
    return render_template('users_list.html', all_users=all_users)


@app.route('/admin/grant_resource', methods=['GET', 'POST'])
@permission_required('manage_users')
def admin_grant_resource():
    all_users = User.query.all()
    if request.method == 'POST':
        u_id = request.form.get('user_id')
        res_id = request.form.get('resource_id')
        grant_resource_permission(u_id, 'document', res_id, 'view')
        return redirect(url_for('admin_grant_resource', success="Entitlement added successfully!"))
    return render_template('grant_resource.html', users=all_users)


@app.route('/request_jit_document/<int:doc_id>')
def request_jit_document(doc_id):
    user = get_current_user_from_session()
    if not user:
        return redirect(url_for('login'))

    new_access = ResourceAccess(
        user_id=user.id,
        resource_type='document',
        resource_id=doc_id,
        permission_type='view',
        expiry_time=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(new_access)
    db.session.commit()
    return redirect(url_for('view_document', doc_id=doc_id))


@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    user = get_current_user_from_session()
    if not user:
        return redirect(url_for('login'))

    has_global = any(p.name == 'view_reports' for p in user.role.permissions)
    has_specific = has_resource_permission(user, 'document', doc_id, 'view')

    if has_global or has_specific:
        source = "Global Role" if has_global else "Specific JIT access"
        return render_template('protected.html', user=user,
                               message=f"Successfully accessed document #{doc_id} via {source}!")
    return render_template('forbidden.html', user=user,
                           error=f"You do not have permission for Document #{doc_id}. A specific JIT permission is required.")

# --- 5.Logout ---
@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_id')

    if session_token:
        delete_server_session(session_token)
    session.clear()

    response = redirect(url_for('login', logout=True))
    response.delete_cookie('session_id')  # Brisenje na cookie-to
    return response


if __name__ == '__main__':
    app.run(debug=True)
