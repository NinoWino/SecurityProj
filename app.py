from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User
from forms import LoginForm, OTPForm, ChangePasswordForm, Toggle2FAForm, ForgotPasswordForm, ResetPasswordForm, DeleteAccountForm, RegisterDetailsForm, VerifyTOTPForm, EmailForm
from datetime import datetime, timedelta
import random
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
import os, requests, pyotp, qrcode, io
from dotenv import load_dotenv
from user_agents import parse as parse_ua
from pytz import timezone
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded


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
    "SESSION_COOKIE_SAMESITE": "Lax",
    "SESSION_COOKIE_SECURE": True
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
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]  # so we control manually
)

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# @app.errorhandler(Exception)
# def handle_unexpected_error(e):
#     return render_template('error.html', message="An unexpected error occurred."), 500

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def on_unauthorized():
    if session.get('last_active'):
        return redirect(url_for('login', message='timeout'))
    return redirect(url_for('login'))

def get_public_ip():
    try:
        res = requests.get('https://api.ipify.org?format=json', timeout=3)
        return res.json().get('ip')
    except Exception:
        return '127.0.0.1'  # fallback

def get_location_data(_unused=None):
    ip = get_public_ip()
    try:
        res = requests.get(f'https://ipwhois.app/json/{ip}', timeout=3)
        data = res.json()
        return {
            'ip': ip,
            'city': data.get('city', 'Unknown'),
            'region': data.get('region', 'Unknown'),
            'country': data.get('country', 'Unknown'),
            'asn': data.get('asn', 'Unknown'),
            'org': data.get('org', 'Unknown'),
            'isp': data.get('isp', 'Unknown'),
            'domain': data.get('domain', 'Unknown'),
            'anonymous': data.get('security', {}).get('anonymous', False),
            'proxy': data.get('security', {}).get('proxy', False),
            'vpn': data.get('security', {}).get('vpn', False),
            'tor': data.get('security', {}).get('tor', False),
            'hosting': data.get('security', {}).get('hosting', False)
        }
    except Exception:
        return {
            'ip': ip,
            'city': 'Unknown',
            'region': 'Unknown',
            'country': 'Unknown',
            'asn': 'Unknown',
            'org': 'Unknown',
            'isp': 'Unknown',
            'domain': 'Unknown',
            'anonymous': False,
            'proxy': False,
            'vpn': False,
            'tor': False,
            'hosting': False
        }



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

def send_login_alert_email(user):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ua_string = request.headers.get('User-Agent', '')
    location = get_location_data()
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
            f"🔌 ISP: {location['isp']}\n"
            f"🏢 Organization: {location['org']}\n"
            f"🌐 Domain: {location['domain']}\n"
            f"📡 ASN: {location['asn']}\n\n"
            f"💻 Device: {device_info}\n"
            f"🕒 Time: {sg_time.strftime('%Y-%m-%d %H:%M:%S')} SGT\n\n"
            f"🛡️ Network Anonymity:\n"
            f"  - VPN: {'Yes' if location['vpn'] else 'No'}\n"
            f"  - Proxy: {'Yes' if location['proxy'] else 'No'}\n"
            f"  - Tor: {'Yes' if location['tor'] else 'No'}\n"
            f"  - Hosting Provider: {'Yes' if location['hosting'] else 'No'}\n\n"
            "If this wasn’t you, please reset your password or contact support immediately."
        )
    )
    try:
        mail.send(msg)
    except Exception as e:
        flash("Failed to send email. Please try again later.", "danger")
        return redirect(url_for('login'))

def send_otp_email(user, subject, body_template):
    from flask_mail import Message
    from datetime import datetime, timedelta
    import random

    code = f"{random.randint(0, 999999):06d}"
    user.otp_code = generate_password_hash(code)
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    msg = Message(
        subject=subject,
        recipients=[user.email],
        body=body_template.format(username=user.username, code=code)
    )
    mail.send(msg)
    return code

def enforce_rate_limit(limit_string, key_prefix, error_message="Too many requests. Please try again later.", wait_seconds=60):
    """
    Globally usable rate limiter.
    - `limit_string`: e.g., "3 per minute"
    - `key_prefix`: unique string (e.g., "login:email@example.com")
    - `error_message`: message to show user on limit breach
    - `wait_seconds`: value to return for UI countdown (optional)

    Returns (None, None) if allowed, else (error_message, wait_seconds)
    """
    try:
        limiter.limit(limit_string, key_func=lambda: key_prefix)(lambda: None)()
        return None, None
    except RateLimitExceeded:
        return error_message, wait_seconds

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/')
def home():
    return render_template('home.html')
# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = LoginForm()
    error = None
    LOCK_DURATION = timedelta(seconds=60)
    MAX_ATTEMPTS = 3

    if form.validate_on_submit():
        stmt = select(User).filter_by(email=form.email.data.strip().lower())
        user = db.session.scalars(stmt).first()

        if user and user.signup_method.lower() != 'email':
            flash(f"This account was created using {user.signup_method.capitalize()}. Please use that login method.", "warning")
            return redirect(url_for('login'))

        if user:
            if user.is_locked:
                if user.last_failed_login and datetime.utcnow() - user.last_failed_login >= LOCK_DURATION:
                    user.failed_attempts = 0
                    user.is_locked = False
                    db.session.commit()
                else:
                    remaining = LOCK_DURATION - (datetime.utcnow() - user.last_failed_login)
                    seconds_left = max(0, int(remaining.total_seconds()))
                    return render_template('login.html', form=form, error="Account locked. Please try again later.",
                                           lockout_seconds=seconds_left)

            if check_password_hash(user.password, form.password.data):
                location = get_location_data()
                current_country = location.get('country')

                if user.region_lock_enabled:
                    if user.last_country and user.last_country != current_country:
                        flash(f"Login blocked: region mismatch. Expected {user.last_country}, got {current_country}.", "danger")
                        return redirect(url_for('login'))
                    elif not user.last_country:
                        user.last_country = current_country
                        db.session.commit()

                if user.preferred_2fa == 'totp' and user.totp_secret:
                    session['pre_2fa_user_id'] = user.id
                    return redirect(url_for('two_factor_totp'))

                if user.two_factor_enabled:
                    session['pre_2fa_user_id'] = user.id
                    code = f"{random.randint(0, 999999):06d}"
                    user.otp_code = generate_password_hash(code)
                    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                    db.session.commit()

                    msg = Message(
                        subject="Your One-Time Login Code",
                        recipients=[user.email],
                        body=f"Hello {user.username},\n\nYour login code is: {code}\nIt expires in 5 minutes."
                    )
                    try:
                        mail.send(msg)
                    except Exception:
                        flash("Failed to send email. Please try again later.", "danger")
                        return redirect(url_for('login'))

                    return redirect(url_for('two_factor'))

                login_user(user)
                session['last_active'] = datetime.utcnow().isoformat()
                user.failed_attempts = 0
                db.session.commit()
                send_login_alert_email(user)
                return redirect(url_for('profile'))

            user.failed_attempts += 1
            user.last_failed_login = datetime.utcnow()
            if user.failed_attempts >= MAX_ATTEMPTS:
                user.is_locked = True
            db.session.commit()
            error = 'Incorrect email or password.'
        else:
            error = 'Email not found.'

    return render_template('login.html', form=form, error=error, message=request.args.get('message'))



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

    if user and user.signup_method.lower() != 'google':
        flash(f"This email is registered {user.signup_method.capitalize()}. Please use the correct login option.", "warning")
        return redirect(url_for('login'))

    if not user:
        try:
            user = User(
                username=user_info.get('name') or email.split('@')[0],
                email=email,
                password=generate_password_hash(os.urandom(16).hex()),
                role_id=1,
                signup_method = 'google'
            )
            db.session.add(user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Account creation via Google failed.", "danger")
            return redirect(url_for('login'))

    location = get_location_data()
    country = location.get('country')

    if user.region_lock_enabled:
        if user.last_country and user.last_country != country:
            flash(f"Login blocked: region mismatch. Expected {user.last_country}, got {country}.", "danger")
            return redirect(url_for('login'))
        elif not user.last_country:
            user.last_country = country
            db.session.commit()

    # ✅ Finalize login
    login_user(user)
    session['last_active'] = datetime.utcnow().isoformat()

    send_login_alert_email(user)

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

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = ForgotPasswordForm()
    error = None

    if form.validate_on_submit():
        error, wait = enforce_rate_limit(
            "3 per minute",
            key_prefix=f"forgot:{request.remote_addr}",
            error_message="Too many OTP requests. Please wait before trying again.",
            wait_seconds=60
        )
        if error:
            session['reset_wait_until'] = (datetime.utcnow() + timedelta(seconds=wait)).isoformat()
            return render_template('forgot_password.html', form=form, error=error, wait_seconds=wait)

        email = form.email.data.strip().lower()
        stmt = select(User).filter_by(email=email)
        user = db.session.scalars(stmt).first()

        if user:
            code = f"{random.randint(0, 999999):06d}"
            user.otp_code = generate_password_hash(code)
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()

            session['reset_user_id'] = user.id
            session['reset_otp_attempts'] = 0
            session['reset_resend_attempts'] = 0
            session['reset_block_until'] = None

            try:
                msg = Message(
                    subject="Reset Password Code",
                    recipients=[user.email],
                    body=f"Hi {user.username},\n\nYour reset code is: {code}\nIt expires in 5 minutes."
                )
                mail.send(msg)
            except Exception:
                error = "Failed to send email. Please try again later."
                return render_template('forgot_password.html', form=form, error=error)

            return redirect(url_for('verify_reset_otp'))

        error = "Email not found."

    return render_template('forgot_password.html', form=form, error=error)

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# 2FA ROUTES
@app.route('/toggle_2fa', methods=['POST'])
@login_required
def toggle_2fa():
    form = Toggle2FAForm()
    if form.validate_on_submit():
        if current_user.two_factor_enabled:
            current_user.two_factor_enabled = False
        else:
            current_user.two_factor_enabled = True
            current_user.preferred_2fa = 'email'
            current_user.totp_secret = None  # ✅ disable authenticator app
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
        elif not check_password_hash(user.otp_code, token):
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

            send_login_alert_email(user)  # ✅ send only after OTP success
            return redirect(url_for('profile'))

    resent = bool(request.args.get('resent'))
    return render_template('two_factor.html', form=form, error=error, resent=resent)

@app.route('/resend_otp/<context>')
def resend_otp(context):
    now = datetime.utcnow()

    # --------- LOGIN (2FA via email) ---------
    if context == 'login':
        user_id = session.get('pre_2fa_user_id')
        if not user_id:
            return redirect(url_for('login'))

        user = db.session.get(User, user_id)

        error, wait = enforce_rate_limit(
            "3 per minute",
            key_prefix=f"resend-login:{user.email}",
            error_message="Too many OTP resends. Please wait before trying again.",
            wait_seconds=60
        )
        if error:
            session['login_wait_until'] = (now + timedelta(seconds=wait)).isoformat()
            return render_template('two_factor.html', form=OTPForm(), error=error, wait_seconds=wait)

        try:
            send_otp_email(
                user,
                subject="Your One-Time Login Code (Resent)",
                body_template="Hello {username},\n\nYour new login code is: {code}\nIt expires in 5 minutes."
            )
        except Exception:
            return render_template('two_factor.html', form=OTPForm(), error="Failed to send email.")

        return render_template('two_factor.html', form=OTPForm(), resent=True)

    # --------- REGISTRATION ---------
    elif context == 'register':
        email = session.get('register_email')
        if not email:
            return render_template('register_email.html', form=EmailForm(), error="Session expired. Please start again.")

        error, wait = enforce_rate_limit(
            "3 per minute",
            key_prefix=f"resend-register:{email}",
            error_message="Too many OTP resends. Please wait before trying again.",
            wait_seconds=60
        )
        if error:
            session['register_wait_until'] = (now + timedelta(seconds=wait)).isoformat()
            return render_template('register_details.html', form=RegisterDetailsForm(), email=email, error=error, wait_seconds=wait)

        class TempUser: pass
        temp = TempUser()
        temp.email = email
        temp.username = email.split("@")[0]

        otp = send_otp_email(
            temp,
            subject="Your New Registration OTP",
            body_template="Your new OTP is: {code}\nIt expires in 5 minutes."
        )
        session['register_otp_hash'] = generate_password_hash(otp)
        session['register_otp_expiry'] = (now + timedelta(minutes=5)).isoformat()
        session['register_otp_attempts'] = 0

        return render_template('register_details.html', form=RegisterDetailsForm(), email=email, resent=True)

    # --------- PASSWORD RESET ---------
    elif context == 'reset':
        user_id = session.get('reset_user_id')
        if not user_id:
            return redirect(url_for('forgot_password'))

        user = db.session.get(User, user_id)

        error, wait = enforce_rate_limit(
            "3 per minute",
            key_prefix=f"resend-reset:{user.email}",
            error_message="Too many OTP resends. Please wait before trying again.",
            wait_seconds=60
        )
        if error:
            session['reset_wait_until'] = (now + timedelta(seconds=wait)).isoformat()
            return render_template('reset_password.html', form=ResetPasswordForm(), error=error, wait_seconds=wait)

        try:
            send_otp_email(
                user,
                subject="Your New Reset Password OTP",
                body_template="Hi {username},\n\nYour new OTP code is: {code}\nIt expires in 5 minutes."
            )
        except Exception:
            return render_template('reset_password.html', form=ResetPasswordForm(), error="Failed to send email.")

        session['reset_otp_attempts'] = 0
        return render_template('reset_password.html', form=ResetPasswordForm(), resent=True)

    # --------- INVALID CONTEXT ---------
    return redirect(url_for('login'))


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
        elif not check_password_hash(user.otp_code, form.otp.data.strip()):
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

@app.route('/setup_totp')
@login_required
def setup_totp():
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32()
        db.session.commit()

    otp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.email,
        issuer_name="MySecureApp"
    )
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/authenticator/setup/start')
@login_required
def setup_totp_step1():
    return render_template('setup_authenticator.html', step='1')

@app.route('/authenticator/setup/qr')
@login_required
def setup_totp_step2():
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32()
        db.session.commit()
    return render_template('setup_authenticator.html', step='2', manual_key=current_user.totp_secret)

@app.route('/authenticator/setup/verify', methods=['GET', 'POST'])
@login_required
def setup_totp_step3():
    form = VerifyTOTPForm()
    error = None

    if request.method == 'POST' and form.validate_on_submit():
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(form.token.data.strip()):
            current_user.preferred_2fa = 'totp'
            current_user.two_factor_enabled = False
            db.session.commit()
            return redirect(url_for('setup_totp_done'))
        else:
            error = "Invalid code. Try again."

    return render_template('setup_authenticator.html', step='3', form=form, error=error)

@app.route('/authenticator/setup/done')
@login_required
def setup_totp_done():
    return render_template('setup_authenticator.html', step='done')


@app.route('/two_factor_totp', methods=['GET', 'POST'])
def two_factor_totp():
    form = OTPForm()
    error = None

    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    totp = pyotp.TOTP(user.totp_secret)

    # Lockout after 3 failed attempts
    attempts = session.get('totp_otp_attempts', 0)
    if attempts >= 3:
        flash('Too many failed attempts. Please log in again.', 'danger')
        session.pop('pre_2fa_user_id', None)
        session.pop('totp_otp_attempts', None)
        return redirect(url_for('login'))

    if form.validate_on_submit():
        token = form.token.data.strip()
        if totp.verify(token):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            session.pop('totp_otp_attempts', None)
            session['last_active'] = datetime.utcnow().isoformat()
            user.failed_attempts = 0
            user.otp_code = None
            user.otp_expiry = None
            db.session.commit()
            send_login_alert_email(user)
            return redirect(url_for('profile'))
        else:
            session['totp_otp_attempts'] = attempts + 1
            error = 'Invalid code. Please try again.'

    return render_template('two_factor_totp.html', form=form, error=error)


@app.route('/authenticator/start')
@login_required
def start_totp_setup():
    return redirect(url_for('setup_totp_step1'))


@app.route('/authenticator/disable')
@login_required
def disable_totp():
    current_user.totp_secret = None
    current_user.preferred_2fa = 'email'
    db.session.commit()
    flash("Authenticator App has been disabled.", "info")
    return redirect(url_for('security'))

@app.route('/fallback_to_email_otp')
def fallback_to_email_otp():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)

    # Generate email OTP
    code = f"{random.randint(0, 999999):06d}"
    user.otp_code = generate_password_hash(code)
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    msg = Message(
        subject="Backup Login Code",
        recipients=[user.email],
        body=(
            f"Hi {user.username},\n\n"
            f"You requested a backup login code.\n\n"
            f"Your OTP is: {code}\n"
            f"It expires in 5 minutes.\n\n"
            f"If you didn't request this, please secure your account."
        )
    )
    try:
        mail.send(msg)
    except Exception as e:
        flash("Failed to send email. Please try again later.", "danger")
        return redirect(url_for('login'))

    return redirect(url_for('two_factor', resent=1))

@app.route('/security')
@login_required
def security():
    toggle_form = Toggle2FAForm()
    return render_template('security.html', toggle_form=toggle_form)

@app.route('/toggle_region_lock', methods=['POST'])
@login_required
def toggle_region_lock():
    current_user.region_lock_enabled = not current_user.region_lock_enabled

    message = ""
    if current_user.region_lock_enabled:
        location = get_location_data()
        country = location.get('country', 'Unknown')
        if not current_user.last_country:
            current_user.last_country = country
        message = f"Region lock enabled. You can now only log in from {current_user.last_country}."
    else:
        message = "Region lock disabled."

    db.session.commit()
    flash(message, "info")
    return redirect(url_for('security'))


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
        error, wait = enforce_rate_limit(
            "3 per minute",
            key_prefix=f"register_email:{request.remote_addr}",
            error_message="Too many registration attempts. Please wait before trying again.",
            wait_seconds=60
        )
        if error:
            session['register_wait_until'] = (datetime.utcnow() + timedelta(seconds=wait)).isoformat()
            return render_template('register_email.html', form=form, error=error, wait_seconds=wait)

        email = form.email.data.strip()

        if User.query.filter_by(email=email).first():
            flash('Email is already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        otp = f"{random.randint(0, 999999):06d}"
        session['register_email'] = email
        session['register_otp_hash'] = generate_password_hash(otp)
        session['register_otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        session['register_otp_attempts'] = 0

        msg = Message(
            subject="Your Registration OTP",
            recipients=[email],
            body=f"Your OTP is: {otp}\nIt expires in 5 minutes."
        )
        try:
            mail.send(msg)
        except Exception as e:
            flash("Failed to send email. Please try again later.", "danger")
            return redirect(url_for('login'))

        flash('OTP sent to your email.', 'info')
        return redirect(url_for('register_details'))

    return render_template('register_email.html', form=form)


@app.route('/register/details', methods=['GET', 'POST'])
def register_details():
    form = RegisterDetailsForm()
    email = session.get('register_email')
    otp_hash = session.get('register_otp_hash')  # stored hash instead of raw OTP
    expiry_str = session.get('register_otp_expiry')
    attempts = session.get('register_otp_attempts', 0)

    if not email or not otp_hash or not expiry_str:
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

        if not check_password_hash(otp_hash, otp_input):
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
            role_id=1,
            signup_method='email'
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