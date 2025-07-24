from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file , abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User, SystemAuditLog, KnownDevice, role_required, LoginAuditLog
from hashlib import sha256
from forms import LoginForm, OTPForm, ChangePasswordForm, Toggle2FAForm, ForgotPasswordForm, ResetPasswordForm, DeleteAccountForm, RegisterDetailsForm, VerifyTOTPForm, EmailForm, BirthdateForm, ChangeEmailForm, LoginRestrictionForm
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
import requests
from models import Product  # at the top with other imports
from forms import ProductForm
import os
from werkzeug.utils import secure_filename
import os
from fpdf import FPDF
from PyPDF2 import PdfReader, PdfWriter
from flask import make_response
from io import BytesIO



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

# Ensure upload folder exists
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


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

def load_disposable_domains():
    with open('disposable_domains.txt', 'r') as f:
        return set(line.strip().lower() for line in f if line.strip())

DISPOSABLE_DOMAINS = load_disposable_domains()

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
#ALL OF HIDAYAT FUNCTIONS ARE HERE

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

def is_user_blocked_by_time(user):
    now = datetime.now().time()
    start = user.login_block_start
    end = user.login_block_end

    if not start or not end:
        return False  # no restriction set

    if start < end:
        return start <= now <= end
    else:
        # Handles overnight span (e.g., 11 PM to 6 AM)
        return now >= start or now <= end

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ALL OF ENZAC FUNCTIONS ARE HERE

# Device hash generator for device recognition
def generate_device_hash(ip, user_agent):
    return sha256(f"{ip}_{user_agent}".encode()).hexdigest()

# Get public IP and location using ipify + ipapi
def get_ip_and_location():
    try:
        ip_response = requests.get('https://api.ipify.org?format=json', timeout=3)
        ip = ip_response.json().get('ip')

        loc_response = requests.get(f'https://ipwhois.app/json/{ip}', timeout=3)
        loc_data = loc_response.json()

        city = loc_data.get('city', '')
        region = loc_data.get('region', '')
        country = loc_data.get('country_name', '')

        location_str = ', '.join(filter(None, [city, region, country]))  # just for display
        return ip, location_str, {'city': city, 'region': region, 'country': country}
    except Exception as e:
        print("GeoIP fetch failed:", e)
        return "Unknown", "Unknown", {'city': '', 'region': '', 'country': 'Unknown'}


# System Audit Log
def log_system_action(user_id, action_type, description=None):
    ip, location = get_ip_and_location()
    user_agent = request.headers.get('User-Agent')

    log = SystemAuditLog(
        user_id=user_id,
        action_type=action_type,
        description=description,
        ip_address=ip,
        user_agent=user_agent,
        location=location
    )
    db.session.add(log)
    db.session.commit()

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ALL OF JUNYN FUNCTIONS PUT HERE






#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ALL OF RENFRED FUNCTIONS PUT HERE







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

    # grab client info
    ip, location_str, _ = get_ip_and_location()
    user_agent = request.headers.get('User-Agent')
    success = False

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        stmt = select(User).filter_by(email=email)
        user = db.session.scalars(stmt).first()
        user_id = user.id if user else None

        if user and not user.is_active:
            flash("Your account has been deactivated. Please contact support.", "danger")
            return redirect(url_for('login'))

        if user:
            # → account lockout
            if user.is_locked:
                if user.last_failed_login and datetime.utcnow() - user.last_failed_login >= LOCK_DURATION:
                    user.failed_attempts = 0
                    user.is_locked = False
                    db.session.commit()
                else:
                    remaining = LOCK_DURATION - (datetime.utcnow() - user.last_failed_login)
                    return render_template('login.html', form=form,
                                           error="Account locked.",
                                           lockout_seconds=int(remaining.total_seconds()))

            # → credential check
            if not check_password_hash(user.password, form.password.data):
                user.failed_attempts += 1
                user.last_failed_login = datetime.utcnow()
                if user.failed_attempts >= MAX_ATTEMPTS:
                    user.is_locked = True
                db.session.commit()
                error = 'Incorrect email or password.'
            else:
                # correct password → reset counter
                user.failed_attempts = 0
                db.session.commit()

                # → region‐lock
                location = get_location_data()
                current_country = location.get('country')
                if user.region_lock_enabled:
                    if user.last_country and user.last_country != current_country:
                        flash(
                          f"Login blocked: region mismatch. Expected {user.last_country}, got {current_country}.",
                          "danger"
                        )
                        return redirect(url_for('login'))
                    elif not user.last_country and current_country:
                        user.last_country = current_country
                        db.session.commit()

                # User defined time based access control
                if is_user_blocked_by_time(user):
                    flash("Login blocked during your restricted hours.", "danger")
                    return redirect(url_for('login'))

                # → TOTP 2FA
                if user.preferred_2fa == 'totp' and user.totp_secret:
                    session['pre_2fa_user_id'] = user.id
                    session['totp_otp_attempts'] = 0  # ← RESET
                    return redirect(url_for('two_factor_totp'))

                # → Email OTP 2FA
                if user.two_factor_enabled:
                    session['pre_2fa_user_id'] = user.id
                    session['login_otp_attempts'] = 0
                    code = f"{random.randint(0, 999999):06d}"
                    user.otp_code   = generate_password_hash(code)
                    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                    db.session.commit()

                    try:
                        mail.send(Message(
                            subject="Your One-Time Login Code",
                            recipients=[user.email],
                            body=f"Hello {user.username},\n\nYour login code is: {code}\nIt expires in 5 minutes."
                        ))
                    except Exception:
                        flash("Failed to send OTP. Try again later.", "danger")
                        return redirect(url_for('login'))

                    return redirect(url_for('two_factor'))

                # → successful login
                login_user(user)
                session['last_active'] = datetime.utcnow().isoformat()
                success = True
                send_login_alert_email(user)

                # log audit
                _, location_str, _ = get_ip_and_location()
                db.session.add(LoginAuditLog(
                    user_id=user.id,
                    email=user.email,
                    success=True,
                    ip_address=ip,
                    user_agent=user_agent,
                    location=location_str
                ))
                db.session.commit()

                # known device tracking
                device_hash = generate_device_hash(ip, user_agent)
                kd = KnownDevice.query.filter_by(
                    user_id=user.id,
                    device_hash=device_hash
                ).first()
                if kd:
                    kd.last_seen = datetime.utcnow()
                else:
                    _, location_str, _ = get_ip_and_location()
                    db.session.add(KnownDevice(
                        user_id=user.id,
                        device_hash=device_hash,
                        ip_address=ip,
                        user_agent=user_agent,
                        location=location_str
                    ))
                db.session.commit()

                return redirect(url_for('profile'))
        else:
            error = 'Email not found.'

        # → log failed attempt (or success=False case)
        _, location_str, _ = get_ip_and_location()
        db.session.add(LoginAuditLog(
            user_id=user_id,
            email=email,
            success=success,
            ip_address=ip,
            user_agent=user_agent,
            location=location_str
        ))
        db.session.commit()

    return render_template('login.html', form=form, error=error,
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

    # 1) Lookup by email
    stmt = select(User).filter_by(email=email)
    user = db.session.scalars(stmt).first()

    # 2) Block non-Google signup methods
    if user and (user.signup_method or '').lower() != 'google':
        flash(
          f"This email is registered via {user.signup_method.capitalize()}. Please use that method.",
          "warning"
        )
        return redirect(url_for('login'))

    # 3) First‐time creation: default 2FA off
    if not user:
        user = User(
            username         = user_info.get('name') or email.split('@')[0],
            email            = email,
            password         = generate_password_hash(os.urandom(16).hex()),
            role_id          = 1,
            signup_method    = 'google',
            two_factor_enabled = False
        )
        db.session.add(user)
        db.session.commit()

    # ── Region Lock (unchanged) ─────────────────────────────────
    country = get_location_data().get('country')
    if user.region_lock_enabled:
        if user.last_country and user.last_country != country:
            flash(
              f"Login blocked: region mismatch. Expected {user.last_country}, got {country}.",
              "danger"
            )
            return redirect(url_for('login'))
        if not user.last_country:
            user.last_country = country
            db.session.commit()

    # User defined time based access control
    if is_user_blocked_by_time(user):
        flash("Login blocked during your restricted hours.", "danger")
        return redirect(url_for('login'))

    # ── TOTP 2FA ───────────────────────────────────────────────
    if user.preferred_2fa == 'totp' and user.totp_secret:
        session['pre_2fa_user_id'] = user.id
        session['totp_otp_attempts'] = 0  # ← Add this
        return redirect(url_for('two_factor_totp'))

    # ── Email-OTP 2FA ─────────────────────────────────────────
    if user.two_factor_enabled:
        session['pre_2fa_user_id'] = user.id
        session['login_otp_attempts'] = 0
        code = f"{random.randint(0, 999999):06d}"
        user.otp_code   = generate_password_hash(code)
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
        db.session.commit()
        mail.send(Message(
            subject   = "Your One-Time Login Code",
            recipients= [user.email],
            body      = f"Hello {user.username},\n\nYour login code is: {code}\nIt expires in 5 minutes."
        ))
        return redirect(url_for('two_factor'))

    # ── Final login ───────────────────────────────────────────
    login_user(user)
    session['last_active'] = datetime.utcnow().isoformat()
    send_login_alert_email(user)

    # Prompt for birthdate if missing
    if not user.birthdate or not user.security_answer_hash or not user.security_question:
        return redirect(url_for('collect_birthdate'))

    return redirect(url_for('profile'))




@app.route('/collect_birthdate', methods=['GET','POST'])
@login_required
def collect_birthdate():
    form = BirthdateForm()

    # Skip if already complete
    if current_user.birthdate and current_user.security_answer_hash and current_user.security_question:
        return redirect(url_for('profile'))

    if form.validate_on_submit():
        current_user.birthdate = form.birthdate.data
        current_user.security_question = form.security_question.data
        current_user.security_answer_hash = generate_password_hash(form.security_answer.data.strip())
        db.session.commit()
        flash('Thanks, your profile has been saved.', 'success')
        return redirect(url_for('profile'))

    return render_template('collect_birthdate.html', form=form)

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
        # rate‐limit to 3/min by IP
        error, wait = enforce_rate_limit(
            "3 per minute",
            key_prefix=f"forgot:{request.remote_addr}",
            error_message="Too many OTP requests. Please wait before trying again.",
            wait_seconds=60
        )
        if error:
            session['reset_wait_until'] = (datetime.utcnow() + timedelta(seconds=wait)).isoformat()
            return render_template('forgot_password.html', form=form,
                                   error=error, wait_seconds=wait)

        email = form.email.data.strip().lower()
        stmt = select(User).filter_by(email=email)
        user = db.session.scalars(stmt).first()

        if user:
            # ❌ Block Google users from using forgot password
            if (user.signup_method or 'email').lower() == 'google':
                error = "This email was registered using Google. Please use Google Login instead."
                return render_template('forgot_password.html', form=form, error=error)

            # ✅ Proceed with OTP generation
            code = f"{random.randint(0, 999999):06d}"
            user.otp_code   = generate_password_hash(code)
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()

            session['reset_user_id']         = user.id
            session['reset_otp_attempts']    = 0
            session['reset_resend_attempts'] = 0
            session['reset_block_until']     = None

            try:
                mail.send(Message(
                    subject="Reset Password Code",
                    recipients=[user.email],
                    body=f"Hi {user.username},\n\nYour reset code is: {code}\nIt expires in 5 minutes."
                ))
            except Exception:
                error = "Failed to send email. Please try again later."
                return render_template('forgot_password.html', form=form, error=error)

            return redirect(url_for('verify_reset_otp'))

        # ❌ No matching user
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
            current_user.totp_secret = None  # disable authenticator app
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

            # ✅ Add audit log here
            ip, location_str, _ = get_ip_and_location()
            user_agent = request.headers.get('User-Agent')
            db.session.add(LoginAuditLog(
                user_id=user.id,
                email=user.email,
                success=True,
                ip_address=ip,
                user_agent=user_agent,
                location=location_str
            ))
            db.session.commit()

            send_login_alert_email(user)
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

    # too many bad OTPs → back to start
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
            # all good → update password
            user.password   = generate_password_hash(form.new_password.data)
            user.otp_code   = None
            user.otp_expiry = None
            db.session.commit()

            # clear any logged‐in session state
            session.pop('reset_user_id', None)
            session.pop('reset_otp_attempts', None)
            logout_user()
            session.clear()

            flash("Password changed successfully. Please log in.", "success")
            return redirect(url_for('login'))

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

            # ✅ Add audit log here
            ip, location_str, _ = get_ip_and_location()
            user_agent = request.headers.get('User-Agent')
            db.session.add(LoginAuditLog(
                user_id=user.id,
                email=user.email,
                success=True,
                ip_address=ip,
                user_agent=user_agent,
                location=location_str
            ))
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

@app.route('/security', methods=['GET', 'POST'])
@login_required
def security():
    toggle_form = Toggle2FAForm()
    restriction_form = LoginRestrictionForm()

    if request.method == 'POST':
        if 'remove_restriction' in request.form:
            current_user.login_block_start = None
            current_user.login_block_end = None
            db.session.commit()
            flash("Login restriction removed.", "info")
            return redirect(url_for('security'))

        if restriction_form.validate_on_submit():
            current_user.login_block_start = restriction_form.block_start.data
            current_user.login_block_end = restriction_form.block_end.data
            db.session.commit()
            flash("Login restriction updated.", "success")
            return redirect(url_for('security'))

    restriction_form.block_start.data = current_user.login_block_start
    restriction_form.block_end.data = current_user.login_block_end

    return render_template('security.html',
                           toggle_form=toggle_form,
                           restriction_form=restriction_form)


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
    from sqlalchemy import func
    import re

    form = EmailForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        local_part = email.split('@')[0]
        domain = email.split('@')[1]

        if domain in DISPOSABLE_DOMAINS:
            flash(f"The domain '{domain}' is a known temporary email provider and is not allowed.", 'danger')
            return redirect(url_for('register_email'))

        # Bot and disposable email patterns
        bot_patterns = [
            r"test\d*@", r"fake\d*@", r"bot\d*@",
            r"(noreply|no-reply|donotreply)",
            r"(mailinator|tempmail|10minutemail|guerrillamail|dispostable|trashmail|maildrop|yopmail|getnada|spamgourmet|sharklasers|mintemail|fenexy|mail.tm|emailtemporario|temporaryemail|throwawaymail)"
        ]

        for pattern in bot_patterns:
            if re.search(pattern, email):
                flash('Suspicious email pattern detected. Please use a real, personal email address.', 'danger')
                return redirect(url_for('register_email'))

        # Block repeated substring usernames (e.g., abcabcabc)
        for i in range(1, len(local_part) // 2):
            segment = local_part[:i]
            repeat_count = len(local_part) // len(segment)
            if segment * repeat_count == local_part:
                flash('Email username appears to be artificially repeated. Please use a real email', 'danger')
                return redirect(url_for('register_email'))

        # Already exists check
        if User.query.filter_by(email=email).first():
            flash('This email is already registered.', 'danger')
            return redirect(url_for('register_email'))

        # Repetition detection: Flag if too many similar usernames exist
        prefix = re.sub(r'\d+$', '', local_part)  # base without trailing digits
        if prefix:
            similar_count = User.query.filter(
                func.lower(User.email).like(f"{prefix.lower()}%@{domain}")
            ).count()
            if similar_count >= 3:
                flash('Too many similar usernames have registered using this email pattern. Try a different email', 'danger')
                return redirect(url_for('register_email'))

        # Generate OTP
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
            phone=form.phone.data.strip() or None,
            birthdate=form.birthdate.data,
            role_id=1
        )

        new_user.security_question = form.security_question.data
        new_user.security_answer_hash = generate_password_hash(form.security_answer.data.strip())
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
    if (current_user.signup_method or 'email').lower() != 'email':
        flash(
            "You cannot change your email address because you signed up via "
            f"{current_user.signup_method.capitalize()}.",
            "warning"
        )
        return redirect(url_for('profile'))

    form = ChangeEmailForm()
    error = None

    if form.validate_on_submit():
        try:
            # normalize to lowercase to avoid dupes
            current_user.email = form.new_email.data.strip().lower()
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
        user = db.session.get(User, current_user.id)

        # Check password
        if not check_password_hash(user.password, form.password.data):
            flash("Incorrect password.", "danger")
            return redirect(url_for('delete_account'))

        # Check security answer
        if not check_password_hash(user.security_answer_hash, form.security_answer.data.strip()):
            flash("Incorrect security answer.", "danger")
            return redirect(url_for('delete_account'))

        try:
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

@app.route('/force_password_reset', methods=['GET', 'POST'])
def force_password_reset():
    from forms import ForcePasswordResetForm
    form = ForcePasswordResetForm()
    user_id = session.get('expired_user_id')

    if not user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    error = None

    if form.validate_on_submit():
        from werkzeug.security import generate_password_hash, check_password_hash

        if not check_password_hash(user.password, form.old_password.data):
            error = 'Current password is incorrect.'
        elif check_password_hash(user.password, form.new_password.data):
            error = 'New password must be different from the old password.'
        elif any(check_password_hash(old, form.new_password.data) for old in user.password_history[-3:]):
            error = 'You cannot reuse one of your last 3 passwords.'
        else:
            new_hash = generate_password_hash(form.new_password.data)
            user.password = new_hash
            user.password_last_changed = datetime.utcnow()
            user.password_history.append(new_hash)
            if len(user.password_history) > 3:
                user.password_history = user.password_history[-3:]

            db.session.commit()
            session.pop('expired_user_id', None)
            flash('Password updated successfully. Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('force_password_reset.html', form=form, error=error)

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/products')
@login_required
def products():
    items = Product.query.all()
    return render_template('product.html', products=items)

@app.route('/product/<int:product_id>')
@login_required
def view_product(product_id):
    item = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=item)


@app.route('/admin/products', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_products():
    form = ProductForm()
    products = Product.query.order_by(Product.created_at.desc()).all()

    if form.validate_on_submit():
        image = request.files.get('image')
        filename = None

        if image:
            # Make sure the upload folder exists
            upload_folder = os.path.join(app.root_path, 'static/uploads')
            os.makedirs(upload_folder, exist_ok=True)

            # Secure and save the file
            filename = secure_filename(image.filename)
            image.save(os.path.join(upload_folder, filename))

        # Create product with uploaded image filename
        new_product = Product(
            name=form.name.data,
            price=form.price.data,
            description=form.description.data,
            image_filename=filename
        )
        db.session.add(new_product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('manage_products'))

    return render_template('admin_products.html', form=form, products=products)

@app.route('/admin/products/delete/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_product(id):
    product = Product.query.get_or_404(id)

    # Delete image file from /static/uploads if it exists
    if product.image_filename:
        image_path = os.path.join(app.root_path, 'static/uploads', product.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully.', 'success')
    return redirect(url_for('manage_products'))
@app.route('/save_cart', methods=['POST'])
@login_required
def save_cart():
    data = request.get_json()

    # Optional: validate the structure of each cart item
    valid_cart = []
    for item in data:
        if all(k in item for k in ('id', 'name', 'price', 'qty')):
            valid_cart.append({
                'id': item['id'],
                'name': item['name'],
                'price': float(item['price']),
                'qty': int(item['qty'])
            })

    session['cart'] = valid_cart
    return jsonify({"message": "Cart saved"}), 200

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'POST':
        # Example: assume you're getting product IDs and quantities from form
        product_ids = request.form.getlist('product_id')
        quantities = request.form.getlist('quantity')

        cart = []
        for pid, qty in zip(product_ids, quantities):
            product = Product.query.get(int(pid))
            if product:
                cart.append({
                    'id': product.id,
                    'name': product.name,
                    'price': product.price,
                    'qty': int(qty)
                })

        session['cart'] = cart
        return redirect(url_for('invoice_ready'))

    products = Product.query.all()
    return render_template('checkout.html', products=products)



@app.route('/invoice', methods=['POST', 'GET'])  # make it flexible
@login_required
def invoice():
    return redirect(url_for('invoice_ready'))


@app.route('/invoice_ready')
@login_required
def invoice_ready():
    user = current_user
    email_prefix = user.email.split('@')[0]
    birthdate = user.birthdate.strftime('%Y%m%d')
    password_hint = f"{email_prefix}{birthdate}"  # This is the actual password

    return render_template("invoice_ready.html", password_hint=password_hint)

@app.route('/download_invoice')
@login_required
def download_invoice():
    user = current_user
    email_prefix = user.email.split('@')[0]
    birthdate = user.birthdate.strftime('%Y%m%d')
    password = f"{email_prefix}{birthdate}"

    cart = session.get('cart', [])
    total = sum(item['price'] * item['qty'] for item in cart)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Invoice", ln=True, align='C')
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Name: {user.username}", ln=True)
    pdf.cell(200, 10, txt=f"Email: {user.email}", ln=True)
    pdf.cell(200, 10, txt=f"Birthdate: {user.birthdate}", ln=True)
    pdf.ln(5)
    pdf.cell(200, 10, txt="Items:", ln=True)

    for item in cart:
        line = f"- {item['name']} x{item['qty']} = ${item['price'] * item['qty']:.2f}"
        pdf.cell(200, 10, txt=line, ln=True)

    pdf.ln(5)
    pdf.cell(200, 10, txt=f"Total: ${total:.2f}", ln=True)
    # Encrypt
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    reader = PdfReader(BytesIO(pdf_bytes))
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)
    writer.encrypt(user_pwd=password)

    encrypted_pdf = BytesIO()
    writer.write(encrypted_pdf)
    encrypted_pdf.seek(0)

    response = make_response(encrypted_pdf.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=invoice.pdf'
    return response

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/user')
@login_required
@role_required(1, 2, 3)
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/staff')
@login_required
@role_required(2, 3)
def staff_dashboard():
    return render_template('staff_dashboard.html')

@app.route('/admin')
@login_required
@role_required(3)
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/overview')
@login_required
@role_required(3)
def admin_overview():
    utc_now = datetime.utcnow()
    day_ago = utc_now - timedelta(days=1)

    total_users = User.query.count()
    new_signups = User.query.filter(User.created_at >= day_ago).count()
    successful_logins_24h = LoginAuditLog.query.filter(
        LoginAuditLog.timestamp >= day_ago,
        LoginAuditLog.success == True
    ).count()

    failed_logins_24h = LoginAuditLog.query.filter(
        LoginAuditLog.timestamp >= day_ago,
        LoginAuditLog.success == False
    ).count()

    deactivated_accounts = User.query.filter_by(is_active=False).count()
    active_today = LoginAuditLog.query.filter(LoginAuditLog.timestamp >= day_ago, LoginAuditLog.success == True).distinct(LoginAuditLog.user_id).count()

    return render_template(
        'admin_overview.html',
        total_users=total_users,
        new_signups=new_signups,
        successful_logins_24h=successful_logins_24h,
        failed_logins_24h=failed_logins_24h,
        active_today=active_today,
        deactivated_accounts=deactivated_accounts
    )

@app.route('/admin/users')
@login_required
@role_required(3)
def manage_users():
    search = request.args.get('search', '').strip()
    role = request.args.get('role', '')

    query = User.query
    if search:
        query = query.filter(
            (User.username.ilike(f"%{search}%")) | (User.email.ilike(f"%{search}%"))
        )
    if role.isdigit():
        query = query.filter_by(role_id=int(role))

    users = query.order_by(User.id.desc()).all()
    return render_template('admin_users.html', users=users, search=search, role_filter=role)

@app.route('/admin/user/add', methods=['GET', 'POST'])
@login_required
@role_required(3)
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role_id = int(request.form['role_id'])

        new_user = User(username=username, email=email, password=password, role_id=role_id)
        db.session.add(new_user)
        db.session.commit()
        flash('New user added.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('admin_user_form.html', action='Add')

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required(3)
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role_id = int(request.form['role_id'])
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('User updated.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('admin_user_form.html', action='Edit', user=user)

@app.route('/admin/user/<int:user_id>/toggle')
@login_required
@role_required(3)
def toggle_user_activation(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"{user.username} is now {'active' if user.is_active else 'deactivated'}.", "info")
    return redirect(url_for('manage_users'))

@app.route('/admin/security_dashboard')
@login_required
@role_required(3)
def security_dashboard():
    logs_query = LoginAuditLog.query

    # Get filter values from request
    email_filter = request.args.get('email')
    location_filter = request.args.get('location')
    success_filter = request.args.get('success')

    if email_filter:
        logs_query = logs_query.filter(LoginAuditLog.email == email_filter)
    if location_filter:
        logs_query = logs_query.filter(LoginAuditLog.location == location_filter)
    if success_filter in ['0', '1']:
        logs_query = logs_query.filter(LoginAuditLog.success == bool(int(success_filter)))

    logs = logs_query.order_by(LoginAuditLog.timestamp.desc()).limit(50).all()
    devices = KnownDevice.query.order_by(KnownDevice.last_seen.desc()).limit(50).all()

    # ✨ Fetch unique filter values
    emails = [e[0] for e in db.session.query(LoginAuditLog.email).distinct().all()]
    locations = [l[0] for l in db.session.query(LoginAuditLog.location).distinct().all()]

    return render_template('security_dashboard.html', logs=logs, devices=devices,
                           emails=emails, locations=locations)

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403


if __name__ == '__main__':
    app.run(debug=True)