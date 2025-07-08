from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User
from forms import LoginForm, OTPForm, ChangePasswordForm, Toggle2FAForm, ForgotPasswordForm, ResetPasswordForm, DeleteAccountForm, RegisterDetailsForm
from datetime import datetime, timedelta
import random
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
import os
from dotenv import load_dotenv
import requests
from user_agents import parse as parse_ua
from pytz import timezone

load_dotenv()

app = Flask(__name__)
# … your existing config …
app.config.update({
    'MAIL_SERVER':   'smtp.gmail.com',
    'MAIL_PORT':     587,
    'MAIL_USE_TLS':  True,
    'MAIL_USERNAME': os.getenv('MAIL_USERNAME'),
    'MAIL_PASSWORD': os.getenv('MAIL_PASSWORD'),
    'MAIL_DEFAULT_SENDER': f"No Reply <{os.getenv('MAIL_USERNAME')}>"
})

mail = Mail(app)
# Config
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
app.config['WTF_CSRF_ENABLED'] = True

app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Session timeout settings
app.permanent_session_lifetime = timedelta(minutes=30)

# Secure cookies
app.config.update({
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax"
})

db.init_app(app)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid email profile'
    }
)


@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def on_unauthorized():
    if session.get('last_active'):
        return redirect(url_for('login', message='timeout'))
    return redirect(url_for('login'))

def get_location_data(ip):
    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=2)
        data = response.json()
        return {
            'ip': ip,
            'city': data.get('city', 'Unknown'),
            'region': data.get('region', 'Unknown'),
            'country': data.get('country_name', 'Unknown')
        }
    except Exception:
        return {'ip': ip, 'city': 'Unknown', 'region': 'Unknown', 'country': 'Unknown'}

def get_device_info(user_agent_string):
    ua = parse_ua(user_agent_string)
    return f"{ua.os.family} {ua.os.version_string} - {ua.browser.family} {ua.browser.version_string}"


@app.before_request
def check_session_timeout():
    if current_user.is_authenticated:
        now = datetime.utcnow()
        last_active = session.get('last_active')
        if last_active:
            last_active = datetime.fromisoformat(last_active)
            if now - last_active > timedelta(minutes=30):
                logout_user()
                session.clear()
                return redirect(url_for('login', message='timeout'))
        session['last_active'] = now.isoformat()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form  = LoginForm()
    error = None

    LOCK_DURATION = timedelta(minutes=20)
    MAX_ATTEMPTS  = 3

    if form.validate_on_submit():
        stmt = select(User).filter_by(email=form.email.data)
        user = db.session.scalars(stmt).first()

        if user:
            # Account lockout check
            if user.is_locked:
                last = user.last_failed_login
                if last and datetime.utcnow() - last >= LOCK_DURATION:
                    user.failed_attempts = 0
                    user.is_locked = False
                    db.session.commit()
                else:
                    error = "Account locked. Please try again later."
                    return render_template('login.html', form=form, error=error)

            # Password check
            if check_password_hash(user.password, form.password.data):
                # Handle 2FA if enabled
                if user.two_factor_enabled:
                    code = f"{random.randint(0, 999999):06d}"
                    user.otp_code = code
                    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                    db.session.commit()

                    msg = Message(
                        subject="Your One-Time Login Code",
                        recipients=[user.email],
                        body=f"Hello {user.username},\n\nYour login code is: {code}\n\nIt expires in 5 minutes."
                    )
                    mail.send(msg)

                    session['pre_2fa_user_id'] = user.id
                    return redirect(url_for('two_factor'))

                # No 2FA: complete login
                login_user(user)
                session['last_active'] = datetime.utcnow().isoformat()
                user.failed_attempts = 0
                db.session.commit()

                # ==== 📧 Send login alert email ====
                ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                ua_string = request.headers.get('User-Agent', '')
                location = get_location_data(ip)
                device_info = get_device_info(ua_string)
                sg_time = datetime.utcnow().replace(tzinfo=timezone('UTC')).astimezone(timezone('Asia/Singapore'))
                msg = Message(
                    subject="New Login to Your Account",
                    recipients=[user.email],
                    body=(
                        f"Hi {user.username},\n\n"
                        f"A new login to your account was detected:\n\n"
                        f"📍 IP Address: {location['ip']}\n"
                        f"🌍 Location: {location['city']}, {location['region']}, {location['country']}\n"
                        f"💻 Device: {device_info}\n"
                        f"🕒 Time: {sg_time.strftime('%Y-%m-%d %H:%M:%S')} SGT\n\n"
                        "If this wasn’t you, please reset your password immediately or contact support."
                    )
                )
                mail.send(msg)
                # ==== ✅ End login alert ====

                return redirect(url_for('profile'))

            # Incorrect password
            user.failed_attempts += 1
            user.last_failed_login = datetime.utcnow()
            if user.failed_attempts >= MAX_ATTEMPTS:
                user.is_locked = True
            db.session.commit()
            error = 'Incorrect email or password.'
        else:
            error = 'Email not found.'

    return render_template('login.html',
                           form=form,
                           error=error,
                           message=request.args.get('message'))

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    try:
        token = google.authorize_access_token()
    except OAuthError:
        flash('Google login was cancelled or failed.', 'danger')
        return redirect(url_for('login'))

    user_info = token.get('userinfo') or google.parse_id_token(token)
    if not user_info:
        flash("Authentication failed. No user info returned.", "danger")
        return redirect(url_for('login'))

    email = user_info.get('email')
    if not email:
        flash("Email not available from Google account.", "danger")
        return redirect(url_for('login'))

    stmt = select(User).filter_by(email=email)
    user = db.session.scalars(stmt).first()

    if not user:
        # Auto-register the user with default 'user' role
        user = User(
            username=user_info.get('name') or email.split('@')[0],
            email=email,
            password=generate_password_hash(os.urandom(16).hex()),  # Random unusable password
            role_id=1  # Default to 'user' role
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    session['last_active'] = datetime.utcnow().isoformat()

    return redirect(url_for('profile'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login', message='logged_out'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    error = None

    if form.validate_on_submit():
        # Verify current password
        if not check_password_hash(current_user.password, form.old_password.data):
            error = 'Current password is incorrect.'
        # Prevent new password == old password
        elif check_password_hash(current_user.password, form.new_password.data):
            error = 'New password must be different from the old password.'
        else:
            # Hash and save the new password
            current_user.password = generate_password_hash(form.new_password.data)
            db.session.commit()

            # Invalidate session and force re-login
            logout_user()
            session.clear()
            return redirect(url_for('login', message='pw_changed'))

    return render_template('change_password.html', form=form, error=error)

@app.route('/toggle_2fa', methods=['POST'])
@login_required
def toggle_2fa():
    form = Toggle2FAForm()
    if form.validate_on_submit():
        current_user.two_factor_enabled = not current_user.two_factor_enabled
        db.session.commit()
    return redirect(url_for('security'))

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    form = OTPForm()
    error = None
    attempts = session.get('login_otp_attempts', 0)

    if attempts >= 3:
        flash('Too many failed attempts. Please log in again.', 'danger')
        session.pop('pre_2fa_user_id', None)
        return redirect(url_for('login'))

    if form.validate_on_submit():
        token = form.token.data.strip()
        if not user.otp_expiry or datetime.utcnow() > user.otp_expiry:
            error = 'Code expired. Please log in again.'
            session.pop('pre_2fa_user_id', None)
        elif token != user.otp_code:
            session['login_otp_attempts'] = attempts + 1
            error = 'Invalid code. Please try again.'
        else:
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            session.pop('login_otp_attempts', None)
            session['last_active'] = datetime.utcnow().isoformat()
            user.failed_attempts = 0
            user.otp_code = None
            user.otp_expiry = None
            db.session.commit()
            return redirect(url_for('profile'))

    resent = bool(request.args.get('resent'))
    return render_template('two_factor.html', form=form, error=error, resent=resent)


@app.route('/resend_code')
def resend_code():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)

    # generate & store new code
    code = f"{random.randint(0, 999999):06d}"
    user.otp_code   = code
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    # email it out
    msg = Message(
        subject="Your One-Time Login Code (Resent)",
        recipients=[user.email],
        body=(
            f"Hello {user.username},\n\n"
            f"Your new login code is: {code}\n\n"
            "It expires in 5 minutes."
        )
    )
    mail.send(msg)

    # redirect back with a flag
    return redirect(url_for('two_factor', resent=1))

@app.route('/resend_register_otp')
def resend_register_otp():
    email = session.get('register_email')
    if not email:
        flash('Session expired. Please start again.', 'danger')
        return redirect(url_for('register_email'))

    otp = f"{random.randint(0, 999999):06d}"
    session['register_otp'] = otp
    session['register_otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
    session['register_otp_attempts'] = 0

    msg = Message(
        subject="Your New Registration OTP",
        recipients=[email],
        body=f"Your new OTP is: {otp}\nIt expires in 5 minutes."
    )
    mail.send(msg)

    flash('A new OTP has been sent.', 'info')
    return redirect(url_for('register_details'))

@app.route('/resend_reset_otp')
def resend_reset_otp():
    if 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))

    user = db.session.get(User, session['reset_user_id'])

    otp = f"{random.randint(0, 999999):06d}"
    user.otp_code = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    session['reset_otp_attempts'] = 0

    msg = Message(
        subject="Your New Reset Password OTP",
        recipients=[user.email],
        body=f"Your new OTP code is: {otp}\nIt expires in 5 minutes."
    )
    mail.send(msg)

    flash('A new OTP has been sent.', 'info')
    return redirect(url_for('verify_reset_otp'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = ForgotPasswordForm()
    error = None

    if form.validate_on_submit():
        stmt = select(User).filter_by(email=form.email.data)
        user = db.session.scalars(stmt).first()
        if user:
            code = f"{random.randint(0, 999999):06d}"
            user.otp_code = code
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()

            msg = Message(
                subject="Reset Password Code",
                recipients=[user.email],
                body=f"Hi {user.username},\n\nYour reset code is: {code}\nIt expires in 5 minutes."
            )
            mail.send(msg)
            session['reset_user_id'] = user.id
            return redirect(url_for('verify_reset_otp'))
        else:
            error = "Email not found."

    return render_template('forgot_password.html', form=form, error=error)

@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))

    user = db.session.get(User, session['reset_user_id'])
    form = ResetPasswordForm()
    error = None
    attempts = session.get('reset_otp_attempts', 0)

    if attempts >= 3:
        flash('Too many incorrect OTP attempts. Please try again.', 'danger')
        session.pop('reset_user_id', None)
        return redirect(url_for('forgot_password'))

    if form.validate_on_submit():
        if datetime.utcnow() > user.otp_expiry:
            error = "OTP expired."
        elif form.otp.data != user.otp_code:
            session['reset_otp_attempts'] = attempts + 1
            error = "Invalid OTP."
        elif check_password_hash(user.password, form.new_password.data):
            error = "New password must be different from the current password."
        else:
            user.password = generate_password_hash(form.new_password.data)
            user.otp_code = None
            user.otp_expiry = None
            db.session.commit()
            session.pop('reset_user_id', None)
            session.pop('reset_otp_attempts', None)
            return redirect(url_for('login', message='pw_changed'))

    return render_template('reset_password.html', form=form, error=error)

@app.route('/security')
@login_required
def security():
    toggle_form = Toggle2FAForm()
    return render_template('security.html', toggle_form=toggle_form)

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/register/email', methods=['GET', 'POST'])
def register_email():
    from forms import EmailForm
    form = EmailForm()

    if form.validate_on_submit():
        email = form.email.data.strip()

        if User.query.filter_by(email=email).first():
            flash('Email is already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        otp = f"{random.randint(0, 999999):06d}"
        session['register_email'] = email
        session['register_otp'] = otp
        session['register_otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        session['register_otp_attempts'] = 0

        msg = Message(
            subject="Your Registration OTP",
            recipients=[email],
            body=f"Your OTP is: {otp}\nIt expires in 5 minutes."
        )
        mail.send(msg)

        flash('OTP sent to your email.', 'info')
        return redirect(url_for('register_details'))

    return render_template('register_email.html', form=form)


@app.route('/register/details', methods=['GET', 'POST'])
def register_details():
    form = RegisterDetailsForm()
    email = session.get('register_email')
    otp = session.get('register_otp')
    expiry_str = session.get('register_otp_expiry')
    attempts = session.get('register_otp_attempts', 0)

    if not email or not otp or not expiry_str:
        flash('Session expired. Start again.', 'danger')
        return redirect(url_for('register_email'))

    otp_expiry = datetime.fromisoformat(expiry_str)

    if attempts >= 3:
        flash('Too many incorrect OTP attempts. Please request a new code.', 'danger')
        session.clear()
        return redirect(url_for('register_email'))

    if form.validate_on_submit():
        otp_input = form.otp.data.strip()

        if datetime.utcnow() > otp_expiry:
            flash('OTP expired.', 'danger')
            session.clear()
            return redirect(url_for('register_email'))

        if otp_input != otp:
            session['register_otp_attempts'] = attempts + 1
            flash('Invalid OTP.', 'danger')
            return render_template('register_details.html', form=form, email=email)

        if User.query.filter_by(username=form.username.data.strip()).first():
            form.username.errors.append('Username already taken.')
            return render_template('register_details.html', form=form, email=email)

        new_user = User(
            username=form.username.data.strip(),
            email=email,
            password=generate_password_hash(form.password.data),
            role_id=1
        )
        db.session.add(new_user)
        db.session.commit()

        session.clear()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register_details.html', form=form, email=email)




@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.route('/product')
@login_required
def product():
    return render_template('product.html')

@app.route('/stafflogin')
def stafflogin():
    return render_template('stafflogin.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/change_username', methods=['GET', 'POST'])
@login_required
def change_username():
    from forms import ChangeUsernameForm
    form = ChangeUsernameForm()
    error = None

    if form.validate_on_submit():
        try:
            current_user.username = form.new_username.data.strip()
            db.session.commit()
            flash('Username changed successfully.', 'success')
            return redirect(url_for('profile'))
        except Exception:
            db.session.rollback()
            error = 'Failed to update username. Please try again.'
            flash(error, 'danger')

    return render_template('change_username.html', form=form, error=error)

@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    from forms import ChangeEmailForm
    form = ChangeEmailForm()
    error = None

    if form.validate_on_submit():
        try:
            current_user.email = form.new_email.data.strip()
            db.session.commit()
            flash('Email changed successfully.', 'success')
            return redirect(url_for('profile'))
        except Exception:
            db.session.rollback()
            error = 'Failed to update email. Please try again.'
            flash(error, 'danger')

    return render_template('change_email.html', form=form, error=error)

@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    from forms import DeleteAccountForm
    form = DeleteAccountForm()

    if form.validate_on_submit():
        try:
            user = db.session.get(User, current_user.id)  # Safely retrieve mapped instance
            logout_user()
            db.session.delete(user)
            db.session.commit()
            session.clear()
            flash('Account deleted successfully.', 'success')
            return redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            flash('Failed to delete account. Please try again.', 'danger')

    return render_template('delete_account.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)



