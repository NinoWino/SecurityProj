from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file , abort , g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User, SystemAuditLog, KnownDevice, role_required, LoginAuditLog
from hashlib import sha256
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
import requests
import uuid
import json

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

def log_system_action(
    user_id,
    action_type,
    description=None,
    log_level='INFO',
    category='GENERAL',
    affected_object_id=None,
    changed_fields=None
):
    try:
        print(f"[DEBUG] log_system_action CALLED: {action_type}, user={user_id}")
        ip, location,_ = get_ip_and_location()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        endpoint = request.endpoint
        http_method = request.method
        session_id = session.get('session_id')

        # ✅ Add these lines
        request_id = getattr(g, 'request_id', None)
        role_id = current_user.role_id if current_user.is_authenticated else None

        # Store changes as JSON if provided as dict
        if isinstance(changed_fields, dict):
            changed_fields = json.dumps(changed_fields)

        log = SystemAuditLog(
            user_id=user_id,
            action_type=action_type,
            description=description,
            log_level=log_level,
            category=category,
            endpoint=endpoint,
            http_method=http_method,
            session_id=session_id,
            affected_object_id=affected_object_id,
            changed_fields=changed_fields,
            ip_address=ip,
            user_agent=user_agent,
            location=location,
            role_id_at_action_time = role_id,
            request_id = request_id
        )
        db.session.add(log)
        db.session.commit()
        print("[DEBUG] log_system_action COMMIT OK")
    except Exception as e:
        print(f"[AuditLog Error] Failed to log action '{action_type}':", e)



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
#
# @login_manager.user_loader
# def load_user(user_id):
#     return db.session.get(User, int(user_id))

@login_manager.user_loader
def load_user(user_id):
    print(f"[USER LOADER] Trying to load user_id: {user_id}")
    try:
        user = db.session.get(User, int(user_id))
        if not user:
            print(f"[USER LOADER] No user found for ID {user_id}")
        return user
    except Exception as e:
        print(f"[USER LOADER] Error loading user {user_id}: {e}")
        return None


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
def track_session():
    print(f"[SESSION FULL DEBUG] session: {dict(session)}")
    print(f"[SESSION DEBUG] session_id: {session.get('session_id')}, current_user: {current_user.get_id()}")
def check_session_timeout():
    # Assign unique session ID if not present
    if 'session_id' not in session:
        import uuid
        session['session_id'] = str(uuid.uuid4())

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

def assign_session_and_request_id():
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    g.request_id = str(uuid.uuid4())
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
    ip, location_str, location_data = get_ip_and_location()
    user_agent = request.headers.get('User-Agent')
    user = None
    success = False

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        stmt = select(User).filter_by(email=email)
        user = db.session.scalars(stmt).first()
        user_id = user.id if user else None

        if user and (user.signup_method or '').lower() != 'email':
            method = (user.signup_method or 'another method').capitalize()
            flash(f"Login method mismatch. Use {method} instead.", "warning")
            return redirect(url_for('login'))

        if user:
            # Lockout check
            if user.is_locked:
                if user.last_failed_login and datetime.utcnow() - user.last_failed_login >= LOCK_DURATION:
                    user.failed_attempts = 0
                    user.is_locked = False
                    db.session.commit()
                else:
                    remaining = LOCK_DURATION - (datetime.utcnow() - user.last_failed_login)
                    return render_template('login.html', form=form, error="Account locked.",
                                           lockout_seconds=int(remaining.total_seconds()))

            if check_password_hash(user.password, form.password.data):
                current_country = location_data.get('country')
                if user.region_lock_enabled:
                    if user.last_country and user.last_country != current_country:
                        # ❗ Optional: log region mismatch
                        log_system_action(
                            user_id=user.id,
                            action_type="Login Blocked",
                            description=f"Region mismatch. Expected {user.last_country}, got {current_country}.",
                            category="AUTH",
                            log_level="WARNING"
                        )
                        flash(f"Region mismatch. Expected {user.last_country}, got {current_country}.", "danger")
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

                # ✅ Successful login
                login_user(user)
                session['last_active'] = datetime.utcnow().isoformat()
                user.failed_attempts = 0
                db.session.commit()
                send_login_alert_email(user)
                success = True

                # Log login success
                db.session.add(LoginAuditLog(
                    user_id=user.id,
                    email=user.email,
                    success=True,
                    ip_address=ip,
                    user_agent=user_agent,
                    location=location_str
                ))

                log_system_action(
                    user_id=user.id,
                    action_type="Login",
                    description="User successfully logged in via email.",
                    category="AUTH"
                )

                # Track known devices
                device_hash = generate_device_hash(ip, user_agent)
                known_device = KnownDevice.query.filter_by(user_id=user.id, device_hash=device_hash).first()
                if known_device:
                    known_device.last_seen = datetime.utcnow()
                else:
                    db.session.add(KnownDevice(
                        user_id=user.id,
                        device_hash=device_hash,
                        ip_address=ip,
                        user_agent=user_agent,
                        location=location_str
                    ))

                db.session.commit()
                return redirect(url_for('profile'))

            # ❌ Failed login
            user.failed_attempts += 1
            user.last_failed_login = datetime.utcnow()
            if user.failed_attempts >= MAX_ATTEMPTS:
                user.is_locked = True
            db.session.commit()
            error = 'Incorrect email or password.'

            # Log failed login
            db.session.add(LoginAuditLog(
                user_id=user.id,
                email=user.email,
                success=False,
                ip_address=ip,
                user_agent=user_agent,
                location=location_str
            ))
            log_system_action(
                user_id=user.id,
                action_type="Login Failed",
                description="Failed login attempt due to incorrect credentials.",
                category="AUTH",
                log_level="WARNING"
            )
            db.session.commit()
        else:
            # Unknown email — log only to LoginAuditLog (no user_id)
            db.session.add(LoginAuditLog(
                user_id=None,
                email=email,
                success=False,
                ip_address=ip,
                user_agent=user_agent,
                location=location_str
            ))
            db.session.commit()
            error = 'Email not found.'

    return render_template('login.html', form=form, error=error, message=request.args.get('message'))

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/user')
@login_required
@role_required(1, 2, 3)
def user_dashboard():
    return render_template('user_dashboard.html')

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

    if user:
        signup_method = user.signup_method or 'another method'
        if signup_method.lower() != 'google':
            flash(f"This email is registered {signup_method.capitalize()}. Please use the correct login option.",
                  "warning")
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

    # ✅ Log the login
    log_system_action(
        user_id=user.id,
        action_type="Login (Google)",
        description="User successfully logged in via Google.",
        category="AUTH"
    )

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

            log_system_action(
                user_id=current_user.id,
                action_type="Password Change",
                description="User changed their password",
                category="SECURITY"
            )

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
        original_value = current_user.two_factor_enabled

        if current_user.two_factor_enabled:
            current_user.two_factor_enabled = False
        else:
            current_user.two_factor_enabled = True
            current_user.preferred_2fa = 'email'
            current_user.totp_secret = None  # disable authenticator app

        db.session.commit()

        # ✅ Log the change with session_id and other metadata
        log_system_action(
            user_id=current_user.id,
            action_type="2FA Toggled",
            description=f"2FA is now {'enabled' if current_user.two_factor_enabled else 'disabled'}",
            category="SECURITY",
            affected_object_id=current_user.id,
            changed_fields={
                "two_factor_enabled": [original_value, current_user.two_factor_enabled]
            },
            session_id=session.get('session_id'),
            role_id_at_action_time=getattr(current_user, 'role_id', None),
            request_id=request.headers.get('X-Request-ID')  # Optional: if you're tracking it
        )

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
            log_system_action(
                user_id=user.id,
                action_type="Password Reset",
                description="User reset password via email OTP",
                category="SECURITY"
            )
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

            log_system_action(
                user_id=current_user.id,
                action_type="Authenticator Setup",
                description="User set up authenticator app (TOTP)",
                category="SECURITY"
            )

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
    log_system_action(
        user_id=current_user.id,
        action_type="Authenticator Disabled",
        description="User disabled TOTP 2FA",
        category="SECURITY"
    )
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
    log_system_action(
        user_id=user.id,
        action_type="2FA Fallback to Email",
        description="User switched from TOTP to email OTP for login",
        category="AUTH"
    )

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
    original_value = current_user.region_lock_enabled
    current_user.region_lock_enabled = not original_value

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

    # ✅ Log the change with session_id and other metadata
    log_system_action(
        user_id=current_user.id,
        action_type="Region Lock Toggled",
        description=message,
        category="SECURITY",
        affected_object_id=current_user.id,
        changed_fields={
            "region_lock_enabled": [original_value, current_user.region_lock_enabled]
        },
        session_id=session.get('session_id'),
        role_id_at_action_time=getattr(current_user, 'role_id', None),
        request_id=request.headers.get('X-Request-ID')  # Optional: for traceability
    )

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

        disposable_domains = [
            "mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com",
            "trashmail.com", "maildrop.cc", "yopmail.com", "getnada.com", "sharklasers.com",
            "spamgourmet.com", "mintemail.com", "fenexy.com", "mail.tm",
            "emailtemporario.com", "temporaryemail.com", "throwawaymail.com", "mytaemin.com"
        ]
        if domain in disposable_domains:
            flash('This email is not allowed for registration.', 'danger')
            return redirect(url_for('register_email'))

        # Bot and disposable email patterns
        bot_patterns = [
            r"test\d*@", r"fake\d*@", r"bot\d*@",
            r"(noreply|no-reply|donotreply)",
            r"(mailinator|tempmail|10minutemail|guerrillamail|dispostable|trashmail|maildrop|yopmail|getnada|spamgourmet|sharklasers|mintemail|fenexy|mail.tm|emailtemporario|temporaryemail|throwawaymail)"
        ]

        for pattern in bot_patterns:
            if re.search(pattern, email):
                flash('This email is not allowed for registration.', 'danger')
                return redirect(url_for('register_email'))

        # Block repeated substring usernames (e.g., abcabcabc)
        for i in range(1, len(local_part) // 2):
            segment = local_part[:i]
            repeat_count = len(local_part) // len(segment)
            if segment * repeat_count == local_part:
                flash('This email is not allowed for registration.', 'danger')
                return redirect(url_for('register_email'))

        # Already exists check
        if User.query.filter_by(email=email).first():
            flash('This email is not allowed for registration.', 'danger')
            return redirect(url_for('register_email'))

        # Repetition detection: Flag if too many similar usernames exist
        prefix = re.sub(r'\d+$', '', local_part)  # base without trailing digits
        if prefix:
            similar_count = User.query.filter(
                func.lower(User.email).like(f"{prefix.lower()}%@{domain}")
            ).count()
            if similar_count >= 3:
                flash('This email is not allowed for registration.', 'danger')
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
            phone=form.phone.data.strip(),
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


@app.route('/product')
@login_required
def product():
    return render_template('product.html')

@app.route('/stafflogin')
def stafflogin():
    return render_template('stafflogin.html')

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
        try:
            username = request.form['username'].strip()
            email = request.form['email'].strip()
            password = request.form['password']
            role_id = int(request.form['role_id'])

            # ✅ Create and hash password using model's method (preferred)
            new_user = User(username=username, email=email, role_id=role_id)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            # ✅ Audit log with all initial fields
            log_system_action(
                user_id=current_user.id,
                action_type="Admin Add User",
                description=f"Created new user: {email}",
                category="ADMIN",
                affected_object_id=new_user.id,
                changed_fields={
                    "username": [None, username],
                    "email": [None, email],
                    "role_id": [None, role_id]
                }
            )

            flash('New user added.', 'success')
            return redirect(url_for('manage_users'))

        except Exception:
            db.session.rollback()
            flash('Failed to add new user.', 'danger')

    return render_template('admin_user_form.html', action='Add')


@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required(3)
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        # ✅ Snapshot original values before applying changes
        original_data = {
            "username": user.username,
            "email": user.email,
            "role_id": user.role_id
        }

        # ✅ Apply new values from form
        user.username = request.form['username'].strip()
        user.email = request.form['email'].strip()
        user.role_id = int(request.form['role_id'])

        # ✅ Detect changes before committing
        changed = detect_changes(user, original_data, ["username", "email", "role_id"])

        try:
            db.session.commit()

            # ✅ Only log if something actually changed
            if changed:
                log_system_action(
                    user_id=current_user.id,
                    action_type="Admin Edit User",
                    description=f"Edited user ID {user.id}",
                    category="ADMIN",
                    affected_object_id=user.id,
                    changed_fields=changed
                )

            flash('User updated.', 'success')
        except Exception as e:
            db.session.rollback()
            flash("Failed to update user. Please try again.", "danger")

        return redirect(url_for('manage_users'))

    return render_template('admin_user_form.html', action='Edit', user=user)

@app.route('/admin/user/<int:user_id>/toggle')
@login_required
@role_required(3)
def toggle_user_activation(user_id):
    user = User.query.get_or_404(user_id)
    original_status = user.is_active
    user.is_active = not original_status
    db.session.commit()

    # ✅ Log the change
    log_system_action(
        user_id=current_user.id,
        action_type="Admin Toggled User Activation",
        description=f"{user.username} is now {'active' if user.is_active else 'deactivated'}",
        category="ADMIN",
        affected_object_id=user.id,
        changed_fields={
            "is_active": [original_status, user.is_active]
        }
    )

    flash(f"{user.username} is now {'active' if user.is_active else 'deactivated'}.", "info")
    return redirect(url_for('manage_users'))

@app.route('/security_dashboard')
@role_required(3)
def security_dashboard():
    # --- LOGIN AUDIT LOG FILTERS ---
    login_query = LoginAuditLog.query
    email = request.args.get('email')
    login_user_id = request.args.get('login_user_id')
    success = request.args.get('success')
    location = request.args.get('location')
    ip_address = request.args.get('ip')
    user_agent = request.args.get('user_agent')
    login_start_date = request.args.get('login_start_date')
    login_end_date = request.args.get('login_end_date')

    if email:
        login_query = login_query.filter(LoginAuditLog.email == email)

    if login_user_id and login_user_id.isdigit():
        login_query = login_query.filter(LoginAuditLog.user_id == int(login_user_id))

    if success in ['0', '1']:
        login_query = login_query.filter(LoginAuditLog.success == (success == '1'))

    if location:
        login_query = login_query.filter(LoginAuditLog.location == location)

    if ip_address:
        login_query = login_query.filter(LoginAuditLog.ip_address.like(f"%{ip_address}%"))

    if user_agent:
        login_query = login_query.filter(LoginAuditLog.user_agent.ilike(f"%{user_agent}%"))

    if login_start_date:
        try:
            start_dt = datetime.strptime(login_start_date, "%Y-%m-%d")
            login_query = login_query.filter(LoginAuditLog.timestamp >= start_dt)
        except ValueError as e:
            print("Start date parsing error:", e)

    if login_end_date:
        try:
            end_dt = datetime.strptime(login_end_date, "%Y-%m-%d") + timedelta(days=1)
            login_query = login_query.filter(LoginAuditLog.timestamp < end_dt)
        except ValueError as e:
            print("End date parsing error:", e)

    login_logs = login_query.order_by(LoginAuditLog.timestamp.desc()).limit(100).all()

    # --- SYSTEM AUDIT LOG FILTERS ---
    audit_query = SystemAuditLog.query

    user_id = request.args.get('user_id')
    action_type = request.args.get('action_type')
    category = request.args.get('category')
    log_level = request.args.get('log_level')
    audit_start_date = request.args.get('audit_start_date')
    audit_end_date = request.args.get('audit_end_date')

    if user_id and user_id.isdigit():
        audit_query = audit_query.filter(SystemAuditLog.user_id == int(user_id))

    if action_type:
        audit_query = audit_query.filter_by(action_type=action_type)

    if category:
        audit_query = audit_query.filter_by(category=category)

    if log_level:
        audit_query = audit_query.filter_by(log_level=log_level)

    if audit_start_date:
        try:
            audit_start_dt = datetime.strptime(audit_start_date, "%Y-%m-%d")
            audit_query = audit_query.filter(SystemAuditLog.timestamp >= audit_start_dt)
        except ValueError as e:
            print("Audit start date error:", e)

    if audit_end_date:
        try:
            audit_end_dt = datetime.strptime(audit_end_date, "%Y-%m-%d") + timedelta(days=1)
            audit_query = audit_query.filter(SystemAuditLog.timestamp < audit_end_dt)
        except ValueError as e:
            print("Audit end date error:", e)

    audit_logs = audit_query.order_by(SystemAuditLog.timestamp.desc()).limit(200).all()

    # --- DROPDOWNS ---
    user_ids = [user.id for user in db.session.query(User.id).distinct().order_by(User.id).all()]
    emails = [row.email for row in db.session.query(LoginAuditLog.email).distinct() if row.email]
    locations = [row.location for row in db.session.query(LoginAuditLog.location).distinct() if row.location]
    action_types = [row.action_type for row in db.session.query(SystemAuditLog.action_type).distinct() if row.action_type]
    categories = [row.category for row in db.session.query(SystemAuditLog.category).distinct() if row.category]

    # --- KNOWN DEVICES ---
    devices = KnownDevice.query.order_by(KnownDevice.last_seen.desc()).limit(100).all()

    return render_template(
        'security_dashboard.html',
        logs=login_logs,
        emails=emails,
        locations=locations,
        devices=devices,
        audit_logs=audit_logs,
        action_types=action_types,
        categories=categories,
        user_ids=user_ids,
    )

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
            # ✅ Snapshot original data
            original_data = {
                "username": current_user.username
            }

            # ✅ Apply change
            current_user.username = form.new_username.data.strip()

            # ✅ Detect what changed
            changed = detect_changes(current_user, original_data, ["username"])

            db.session.commit()

            # ✅ Only log if a change actually occurred
            if changed:
                log_system_action(
                    user_id=current_user.id,
                    action_type="Username Change",
                    description=f"User changed their username",
                    category="PROFILE",
                    affected_object_id=current_user.id,
                    changed_fields=changed
                )

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
            old_email = current_user.email
            current_user.email = form.new_email.data.strip()
            db.session.commit()

            log_system_action(
                user_id=current_user.id,
                action_type="Email Change",
                description=f"Changed email from {old_email} to {current_user.email}",
                category="PROFILE",
                changed_fields={"email": [old_email, current_user.email]}
            )

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

        if not check_password_hash(user.password, form.password.data):
            flash("Incorrect password.", "danger")
            return redirect(url_for('delete_account'))

        if not check_password_hash(user.security_answer_hash, form.security_answer.data.strip()):
            flash("Incorrect security answer.", "danger")
            return redirect(url_for('delete_account'))

        try:
            log_system_action(
                user_id=user.id,
                action_type="Account Deletion",
                description="User deleted their account.",
                category="SECURITY",
                affected_object_id=user.id,
                changed_fields={
                    "account_status": ["active", "deleted"],
                    "username": user.username,
                    "email": user.email
                }
            )

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
            old_hash = user.password

            new_hash = generate_password_hash(form.new_password.data)
            user.password = new_hash
            user.password_last_changed = datetime.utcnow()
            user.password_history.append(new_hash)
            if len(user.password_history) > 3:
                user.password_history = user.password_history[-3:]

            db.session.commit()

            log_system_action(
                user_id=user.id,
                action_type="Forced Password Reset",
                description="User reset password after expiration.",
                category="SECURITY",
                changed_fields={"password": ["previous_hash", "new_hash_truncated"]}
            )

            session.pop('expired_user_id', None)
            flash('Password updated successfully. Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('force_password_reset.html', form=form, error=error)


@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'),

def detect_changes(obj, original_data, fields):
    """
    Compare original_data (dict of field -> old_value) to current values on obj.
    Returns a dict of changed fields: field_name -> [old, new]
    """
    changes = {}
    for field in fields:
        old = original_data.get(field)
        new = getattr(obj, field, None)
        if old != new:
            changes[field] = [old, new]
    return changes

if __name__ == '__main__':
    app.run(debug=True)