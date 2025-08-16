from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file , abort, jsonify,g,Blueprint
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select,func,distinct, desc
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User, SystemAuditLog, KnownDevice, role_required, LoginAuditLog
from hashlib import sha256
from forms import (
    LoginForm, OTPForm, ChangePasswordForm, Toggle2FAForm,
    ForgotPasswordForm, ResetPasswordForm, DeleteAccountForm,
    RegisterDetailsForm, VerifyTOTPForm, EmailForm, BirthdateForm,
    ChangeEmailForm, LoginRestrictionForm, IPWhitelistForm
)
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
import os, requests, pyotp, qrcode, io, secrets, json ,uuid,random,re
from dotenv import load_dotenv
from user_agents import parse as parse_ua
from pytz import timezone
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from models import Product  # at the top with other imports
from forms import ProductForm
from werkzeug.utils import secure_filename
from fpdf import FPDF
from PyPDF2 import PdfReader, PdfWriter
from flask import make_response
from io import BytesIO
from collections import Counter
from urllib.parse import quote_plus
from flask_wtf import CSRFProtect
import inspect as _inspect
import re as _re
import ipaddress as _ipaddress



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

csrf = CSRFProtect(app)

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


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(e):
    referer = request.referrer or url_for('login')  # fallback if no referrer
    flash("Too many requests. Please wait and try again.", "warning")
    return redirect(referer)

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

@app.before_request
def attach_request_ids():
    if 'session_id' not in session:
        session['session_id'] = uuid.uuid4().hex
    g.request_id = uuid.uuid4().hex

def __audit_log_safe(action, **kwargs):
    """
    Call your existing log_system_action(...) safely.
    - If your helper accepts these kwargs, they'll be passed through.
    - If not, we filter to only accepted parameters.
    - If still incompatible, we swallow errors so logging never breaks main flows.
    """
    try:
        sig = _inspect.signature(log_system_action)  # your existing helper
        accepted = {k: v for k, v in kwargs.items() if k in sig.parameters}
        if "action" in sig.parameters:
            return log_system_action(action=action, **accepted)
        else:
            # Best-effort positional call (only if your helper expects it)
            return log_system_action(action, *accepted.values())
    except Exception:
        # Never allow logging to change behavior
        pass
# ---------- END: AUDIT LOGGING SAFE ADAPTER ----------

def __parse_ip_list__audit(raw):
    """Parse free-form IP/CIDR text/list into a sorted unique list of strings."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        parts = list(map(str, raw))
    else:
        parts = [p.strip() for p in _re.split(r'[,\n\r\t ]+', str(raw)) if p and p.strip()]

    out = []
    for p in parts:
        try:
            net = _ipaddress.ip_network(p, strict=False)  # accepts IP or CIDR
            out.append(str(net))
            continue
        except ValueError:
            pass
        try:
            ip = _ipaddress.ip_address(p)
            out.append(str(ip))
        except ValueError:
            pass
    return sorted(set(out))

def __diff_lists__audit(old_list, new_list):
    old_set, new_set = set(old_list or []), set(new_list or [])
    added = sorted(list(new_set - old_set))
    removed = sorted(list(old_set - new_set))
    return added, removed
# ---------- END: IP WHITELIST HELPERS ----------

def _as_json(val):
    if val is None:
        return None
    if isinstance(val, str):
        return val
    try:
        return json.dumps(val, ensure_ascii=False, separators=(',',':'))
    except Exception:
        return str(val)
@app.post('/admin/user/<int:user_id>/force-reset')
@login_required
@role_required(3)
def admin_force_password_reset(user_id):
    user = User.query.get_or_404(user_id)

    # Optional: prevent self-targeting
    if user.id == current_user.id:
        flash("You cannot force a password reset for your own account.", "warning")
        return redirect(url_for('manage_users'))

    # Flip the flag
    previous = getattr(user, 'force_password_reset', False)
    user.force_password_reset = True
    db.session.commit()


    # Audit
    try:
        log_system_action(
            user_id=current_user.id,
            action_type="Admin Force Password Reset",
            description=f"Forced password reset for user_id={user.id} ({user.email})",
            category="ADMIN",
            affected_object_id=user.id,
            changed_fields={"force_password_reset": [previous, True]}
        )
    except Exception as e:
        print("audit log failed:", e)

    flash(f"'{user.username}' will be prompted to change password on next login.", "success")
    return redirect(url_for('manage_users'))


def log_system_action(
    user_id,
    action_type,
    description=None,
    log_level='INFO',
    category='GENERAL',
    affected_object_id=None,
    changed_fields=None,
    session_id=None,
    role_id_at_action_time=None,
    request_id=None
):
    try:
        ip, location, _ = get_ip_and_location()
        user_agent  = request.headers.get('User-Agent', 'Unknown')
        endpoint    = request.endpoint
        http_method = request.method

        # resolve runtime values safely
        session_id  = session_id or session.get('session_id')
        request_id  = request_id or getattr(g, 'request_id', None)
        role_id     = role_id_at_action_time or (current_user.role_id if current_user.is_authenticated else None)

        changed_fields = _as_json(changed_fields)

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
            role_id_at_action_time=role_id,
            request_id=request_id
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"[AuditLog Error] Failed to log '{action_type}': {e}")

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ALL OF JUNYN FUNCTIONS PUT HERE






#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ALL OF RENFRED FUNCTIONS PUT HERE
def _risk_level(score: int) -> str:
    # Tweak ranges anytime; they’re also shown on the page
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Moderate"
    if score >= 1:
        return "Low"
    return "Very Low"

def _reason_from_ipqs(data: dict) -> str:
    """
    Build a readable reason string from IPQS JSON flags.
    """
    flags = []
    if data.get("vpn") or data.get("active_vpn"):
        flags.append("VPN detected")
    if data.get("proxy") or data.get("active_proxy") or data.get("open_proxy"):
        flags.append("Proxy detected")
    if data.get("tor") or data.get("active_tor"):
        flags.append("Tor exit node")
    if data.get("recent_abuse"):
        flags.append("Recent abuse reports")
    if data.get("bot_status"):
        flags.append("Automated/bot-like behavior")
    # Hosting / data center style connections
    ct = (data.get("connection_type") or "").lower()
    if "hosting" in ct or data.get("datacenter") or data.get("is_datacenter"):
        flags.append("Data center/hosting network")

    return ", ".join(flags) if flags else "No risk indicators reported"

def check_fraud_risk(email=None, ip=None, user_agent=None, phone=None):
    """
    Returns a dict like:
      { 'score': int, 'risky': bool, 'level': str, 'reason': str, 'raw': {...} }
    Provider: IPQS (header auth).
    """
    provider = (os.getenv('FRAUD_API_PROVIDER') or '').lower()
    api_key  = os.getenv('FRAUD_API_KEY')
    if not provider or not api_key or not ip:
        return {'score': 0, 'risky': False, 'level': _risk_level(0),
                'reason': 'Fraud check disabled or missing IP', 'raw': {}}

    try:
        if provider == 'ipqs':
            url = "https://ipqualityscore.com/api/json/ip"
            params = {
                "ip": ip,
                "strictness": 1,
                "fast": "true",
                "allow_public_access_points": "true",
                "mobile": "true",
                "user_agent": quote_plus(user_agent or ''),
            }
            headers = {"IPQS-KEY": api_key}
            r = requests.get(url, params=params, headers=headers, timeout=4)
            data = r.json()
            score = int(data.get('fraud_score', 0))
            risky_flags = any(data.get(k) for k in ('vpn', 'proxy', 'tor', 'bot_status', 'recent_abuse'))
            return {
                'score': score,
                'risky': risky_flags,
                'level': _risk_level(score),
                'reason': _reason_from_ipqs(data),
                'raw': data
            }

        return {'score': 0, 'risky': False, 'level': _risk_level(0),
                'reason': 'Unknown provider', 'raw': {}}

    except Exception as e:
        return {'score': 0, 'risky': False, 'level': _risk_level(0),
                'reason': f'Provider error: {e}', 'raw': {}}


def log_fraud_event(user_id, where, risk, ip=None, user_agent=None, extra=None):
    """
    where: 'login' | 'google' | 'register' | 'manual'
    Writes a JSON summary to SystemAuditLog.description (visible to admin).
    NOTE: we intentionally do NOT include the provider here.
    """
    try:
        payload = {
            "fraud_score": risk.get("score"),
            "risky": bool(risk.get("risky")),
            "level": risk.get("level"),
            "reasons": risk.get("reason"),
            "ip": ip,
            "ua": (user_agent or "")[:200],
            "ts": datetime.utcnow().isoformat() + "Z",
        }
        if extra:
            payload["extra"] = extra

        entry = SystemAuditLog(
            user_id=user_id,
            action_type=f"fraud_check_{where}",
            description=json.dumps(payload)
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        print("log_fraud_event failed:", e)

@app.route('/admin/fraud')
@login_required
@role_required(3)  # keep your guards if you had them
def admin_fraud():
    logs = SystemAuditLog.query\
        .filter(SystemAuditLog.action_type.like('fraud_check_%'))\
        .order_by(SystemAuditLog.id.desc())\
        .limit(200).all()

    # ---- Bulk fetch user emails for rows that have a user_id
    user_ids = {row.user_id for row in logs if row.user_id is not None}
    id_to_email = {}
    if user_ids:
        users = User.query.filter(User.id.in_(user_ids)).all()
        id_to_email = {u.id: (u.email or "") for u in users}

    rows = []
    for row in logs:
        try:
            d = json.loads(row.description or "{}")
        except Exception:
            d = {}

        score = int(d.get("fraud_score") or 0)
        level = d.get("level") or _risk_level(score)
        reasons = d.get("reasons") or d.get("reason") or "—"
        where = (row.action_type or "").replace("fraud_check_", "")

        # Prefer DB email when user_id exists; otherwise use payload's email (register flow)
        email = id_to_email.get(row.user_id) or d.get("email") or "—"

        rows.append({
            "id": row.id,
            "when": getattr(row, "created_at", None) or getattr(row, "timestamp", None),
            "user_id": row.user_id,
            "email": email,
            "where": where,
            "score": score,
            "level": level,
            "risky": d.get("risky"),
            "ip": d.get("ip"),
            "reasons": reasons,
        })

    risk_legend = [
        {"label": "Very Low", "range": "0"},
        {"label": "Low",      "range": "1–39"},
        {"label": "Moderate", "range": "40–69"},
        {"label": "High",     "range": "70–84"},
        {"label": "Critical", "range": "85–100"},
    ]
    return render_template('admin_fraud.html', rows=rows, risk_legend=risk_legend)





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

    # Handle backup code submission (from modal)
    if request.method == 'POST' and 'backup_code' in request.form:
        email_entered = request.form.get('email', '').strip().lower()
        code_entered = request.form['backup_code'].strip()
        stmt = select(User).filter_by(email=request.form.get('email', '').strip().lower())
        user = db.session.scalars(stmt).first()

        if user and user.backup_codes:
            codes = user.backup_codes.splitlines()
            for hashed in codes:
                if check_password_hash(hashed, code_entered):
                    # Valid backup code → consume it
                    codes.remove(hashed)
                    user.backup_codes = "\n".join(codes) if codes else None
                    db.session.commit()
                    __audit_log_safe(
                        "2FA_BACKUP_CODE_USED",
                        user_id=user.id,
                        status="success",
                        severity="info",
                        ip_address=ip,
                        user_agent=user_agent,
                        location=location_str,
                        message="Backup code used for 2FA during login.",
                        extra={"remaining_backup_codes": len(codes)}
                    )
                    session['bypass_security'] = True
                    session['last_active'] = datetime.utcnow().isoformat()
                    login_user(user)

                    flash("Logged in using backup code. Security restrictions bypassed.", "info")
                    return redirect(url_for('profile'))

        flash("Invalid or used backup code.", "danger")
        __audit_log_safe(
            "2FA_BACKUP_CODE_FAILED",
            user_id=getattr(user, "id", None),
            status="failed",
            severity="warning",
            ip_address=ip,
            user_agent=user_agent,
            location=location_str,
            message="Invalid backup code submitted.",
            extra={"email_entered": email_entered}
        )
        return redirect(url_for('login'))

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
                # correct password → reset counter
                user.failed_attempts = 0
                db.session.commit()

                # → region‐lock
                location = get_location_data()
                current_country = location.get('country')
                country = get_location_data().get('country')

                if user.region_lock_enabled and not session.get('bypass_security'):
                    if user.last_country and user.last_country != current_country:
                        session['backup_user_id'] = user.id  # Store for modal use
                        log_system_action(
                            user_id=user.id,
                            action_type="Login Blocked",
                            description=f"Region mismatch. Expected {user.last_country}, got {current_country}.",
                            category="AUTH",
                            log_level="WARNING"
                        )

                        flash(Markup(
                            f"Login blocked: region mismatch. Expected <strong>{user.last_country}</strong>, got <strong>{current_country}</strong>. "
                            '<a href="#" data-bs-toggle="modal" data-bs-target="#backupCodeModal">Use Backup Code</a> to override.'
                        ), "danger")
                        return redirect(url_for('login'))

                    elif not user.last_country and current_country:
                        user.last_country = current_country
                        db.session.commit()

                # User defined time based access control
                if is_user_blocked_by_time(user) and not session.get('bypass_security'):
                    session['backup_user_id'] = user.id
                    flash(Markup(
                        'Login blocked during your restricted hours. '
                        '<a href="#" data-bs-toggle="modal" data-bs-target="#backupCodeModal">Use Backup Code</a> to override.'
                    ), "danger")
                    return redirect(url_for('login'))

                user_ip = get_public_ip()
                if user.ip_whitelist and not session.get('bypass_security'):
                    allowed_ips = [ip.strip() for ip in user.ip_whitelist.split(",")]
                    if user_ip not in allowed_ips:
                        session['backup_user_id'] = user.id
                        flash(Markup(
                            'Your IP is not authorized. <a href="#" data-bs-toggle="modal" data-bs-target="#backupCodeModal">Use Backup Code</a> to override.'
                        ), "danger")
                        return redirect(url_for('login'))

                # ---- Risk-based fraud check (IPQS) ----
                threshold = int(os.getenv('FRAUD_THRESHOLD', '75'))
                action = (os.getenv('FRAUD_FAIL_ACTION', 'step_up') or 'step_up').lower()

                risk = check_fraud_risk(email=user.email, ip=ip, user_agent=user_agent)
                log_fraud_event(user_id=user.id, where='login', risk=risk, ip=ip, user_agent=user_agent)

                if risk.get('score', 0) >= threshold or risk.get('risky'):
                    if action == 'block':
                        flash("Your sign-in looks risky and was blocked. Please contact support.", "danger")
                        return redirect(url_for('login'))

                    # Step-up to Email OTP
                    session['pre_2fa_user_id'] = user.id
                    session['login_otp_attempts'] = 0
                    code = f"{random.randint(0, 999999):06d}"
                    user.otp_code = generate_password_hash(code)
                    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                    db.session.commit()

                    try:
                        mail.send(Message(
                            subject="Extra Verification Required",
                            recipients=[user.email],
                            body=f"Hi {user.username},\n\nWe detected a risky sign-in. Your verification code is: {code}\nIt expires in 5 minutes."
                        ))
                    except Exception:
                        flash("Failed to send OTP. Try again later.", "danger")
                        return redirect(url_for('login'))

                    flash("We detected a risky sign-in. Please complete the one-time code we emailed you.", "warning")
                    return redirect(url_for('two_factor'))

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
                # ---- Forced password reset gate (admin-triggered) ----
                if getattr(user, 'force_password_reset', False):
                    # Do NOT log them in yet; send them to change their password
                    session['expired_user_id'] = user.id  # optional: reuse your existing flow var
                    flash("Please set a new password to continue.", "warning")
                    return redirect(url_for('change_password'))

                # → successful login
                login_user(user)
                session['last_active'] = datetime.utcnow().isoformat()
                success = True
                session.pop('bypass_security', None)
                session.pop('backup_user_id', None)
                send_login_alert_email(user)

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
    location = get_location_data()
    current_country = location.get('country')
    if user.region_lock_enabled and not session.get('bypass_security'):
        if user.last_country and user.last_country != current_country:
            session['backup_user_id'] = user.id  # Store for modal use
            flash(Markup(
                f"Login blocked: region mismatch. Expected <strong>{user.last_country}</strong>, got <strong>{current_country}</strong>. "
                '<a href="#" data-bs-toggle="modal" data-bs-target="#backupCodeModal">Use Backup Code</a> to override.'
            ), "danger")
            return redirect(url_for('login'))
        if not user.last_country:
            user.last_country = current_country
            db.session.commit()
            # ✅ Log the login
        log_system_action(
            user_id=user.id,
            action_type="Login (Google)",
            description="User successfully logged in via Google.",
            category="AUTH"
        )

    # User defined time based access control
    if is_user_blocked_by_time(user) and not session.get('bypass_security'):
        session['backup_user_id'] = user.id
        flash(Markup(
            'Login blocked during your restricted hours. '
            '<a href="#" data-bs-toggle="modal" data-bs-target="#backupCodeModal">Use Backup Code</a> to override.'
        ), "danger")
        return redirect(url_for('login'))

    user_ip = get_public_ip()
    if user.ip_whitelist and not session.get('bypass_security'):
        allowed_ips = [ip.strip() for ip in user.ip_whitelist.split(",")]
        if user_ip not in allowed_ips:
            session['backup_user_id'] = user.id
            flash(Markup(
                'Your IP is not authorized. <a href="#" data-bs-toggle="modal" data-bs-target="#backupCodeModal">Use Backup Code</a> to override.'
            ), "danger")
            return redirect(url_for('login'))

    # ---- Risk-based fraud check (Google sign-in) ----
    threshold = int(os.getenv('FRAUD_THRESHOLD', '75'))
    action = (os.getenv('FRAUD_FAIL_ACTION', 'step_up') or 'step_up').lower()

    ip, _, _ = get_ip_and_location()
    user_agent = request.headers.get('User-Agent')

    risk = check_fraud_risk(email=user.email, ip=ip, user_agent=user_agent)
    log_fraud_event(user_id=user.id, where='google', risk=risk, ip=ip, user_agent=user_agent)

    if risk.get('score', 0) >= threshold or risk.get('risky'):
        if action == 'block':
            flash("Your sign-in looks risky and was blocked. Please contact support.", "danger")
            return redirect(url_for('login'))

        # Step-up to Email OTP
        session['pre_2fa_user_id'] = user.id
        session['login_otp_attempts'] = 0
        code = f"{random.randint(0, 999999):06d}"
        user.otp_code = generate_password_hash(code)
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
        db.session.commit()

        mail.send(Message(
            subject="Extra Verification Required",
            recipients=[user.email],
            body=f"Hi {user.username},\n\nWe detected a risky sign-in. Your verification code is: {code}\nIt expires in 5 minutes."
        ))
        flash("We detected a risky sign-in. Please complete the one-time code we emailed you.", "warning")
        return redirect(url_for('two_factor'))

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
    success = True
    session.pop('bypass_security', None)
    session.pop('backup_user_id', None)
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
            # If this was admin-forced, clear the flag now
            if hasattr(current_user, 'force_password_reset') and current_user.force_password_reset:
                current_user.force_password_reset = False
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
@limiter.limit("3 per minute", key_func=get_remote_address)
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = ForgotPasswordForm()
    error = None

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        stmt = select(User).filter_by(email=email)
        user = db.session.scalars(stmt).first()

        if user:
            if (user.signup_method or 'email').lower() == 'google':
                error = "This email was registered using Google. Please use Google Login instead."
                return render_template('forgot_password.html', form=form, error=error)

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
    backup_code_error = None
    attempts = session.get('login_otp_attempts', 0)

    # ✅ Backup code modal submission
    if request.method == 'POST' and 'backup_code' in request.form:
        entered = request.form.get('backup_code', '').strip()
        if user.backup_codes:
            codes = user.backup_codes.splitlines()
            for hashed in codes:
                if check_password_hash(hashed, entered):
                    codes.remove(hashed)
                    user.backup_codes = "\n".join(codes) if codes else None
                    db.session.commit()

                    session.pop('pre_2fa_user_id', None)
                    session['bypass_security'] = True
                    login_user(user)
                    session['last_active'] = datetime.utcnow().isoformat()

                    # Audit log
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
                    flash("Logged in using backup code.", "info")
                    return redirect(url_for('profile'))
        backup_code_error = "Invalid or used backup code."

    # ✅ Standard OTP check
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

    if attempts >= 3:
        flash('Too many failed attempts. Please log in again.', 'danger')
        session.pop('pre_2fa_user_id', None)
        return redirect(url_for('login'))

    resent = bool(request.args.get('resent'))
    return render_template('two_factor.html', form=form, error=error,
                           backup_code_error=backup_code_error, resent=resent)

@app.route('/resend_otp/<context>')
@limiter.limit("3 per minute", key_func=lambda: f"resend-otp:{session.get('register_email') or session.get('pre_2fa_user_id') or session.get('reset_user_id') or get_remote_address()}")
def resend_otp(context):
    now = datetime.utcnow()

    # --------- LOGIN (2FA via email) ---------
    if context == 'login':
        user_id = session.get('pre_2fa_user_id')
        if not user_id:
            return redirect(url_for('login'))

        user = db.session.get(User, user_id)

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
def verify_reset_otp(): #THIS IS OTP FOR RESET PASSWORD
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

            log_system_action(
                user_id=user.id,
                action_type="Password Reset",
                description="User reset password via email OTP",
                category="SECURITY"
            )

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

@app.route('/security', methods=['GET', 'POST'])
@login_required
def security():
    toggle_form = Toggle2FAForm()
    restriction_form = LoginRestrictionForm()
    ip_form = IPWhitelistForm()

    # --- Handle Close Backup Modal ---
    if 'close_backup_modal' in request.form:
        session.pop('backup_codes', None)
        return redirect(url_for('security'))

    # --- Handle Remove IP Whitelist ---
    if 'remove_ip_whitelist' in request.form:
        current_user.ip_whitelist = None
        db.session.commit()
        __audit_log_safe(
            "IP_WHITELIST_REMOVED",
            user_id=current_user.id,
            status="success",
            severity="info",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            location=None,
            message="User removed their IP whitelist.",
            extra={}
        )
        flash("IP whitelist removed.", "info")
        return redirect(url_for('security'))

    # --- Handle Update IP Whitelist ---
    if 'ip_submit' in request.form:
        if ip_form.validate_on_submit():
            raw_input = ip_form.whitelist.data.strip()
            clean_ips = ",".join(sorted(set(ip.strip() for ip in raw_input.split(",") if ip.strip())))
            current_user.ip_whitelist = clean_ips or None
            db.session.commit()
            __audit_log_safe(
                "IP_WHITELIST_UPDATED",
                user_id=current_user.id,
                status="success",
                severity="info",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
                location=None,
                message="User updated their IP whitelist.",
                extra={"new_whitelist": clean_ips}
            )
            flash("IP whitelist updated.", "success")
            flash(f"Currently allowed IPs: {clean_ips}", "info")
            return redirect(url_for('security'))
        else:
            flash("Invalid IP input. Please check your entries.", "danger")

    # --- Handle Remove Time Restriction ---
    if 'remove_restriction' in request.form:
        current_user.login_block_start = None
        current_user.login_block_end = None
        db.session.commit()
        flash("Login restriction removed.", "info")
        return redirect(url_for('security'))

    # --- Handle Login Restriction ---
    if 'restriction_submit' in request.form:
        if restriction_form.validate_on_submit():
            current_user.login_block_start = restriction_form.block_start.data
            current_user.login_block_end = restriction_form.block_end.data
            db.session.commit()
            flash("Login restriction updated.", "success")
            return redirect(url_for('security'))

    # --- Prepopulate forms on GET ---
    ip_form.whitelist.data = current_user.ip_whitelist or ""
    restriction_form.block_start.data = current_user.login_block_start
    restriction_form.block_end.data = current_user.login_block_end

    return render_template('security.html',
                           toggle_form=toggle_form,
                           restriction_form=restriction_form,
                           ip_form=ip_form,
                           user_ip=get_public_ip())

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

@app.route('/generate_backup_codes', methods=['POST'])
@login_required
def generate_backup_codes():
    # Generate 8 one-time use codes
    raw_codes = [secrets.token_hex(4).upper() for _ in range(8)]
    hashed_codes = [generate_password_hash(code) for code in raw_codes]

    current_user.backup_codes = "\n".join(hashed_codes)
    db.session.commit()

    __audit_log_safe(
        "2FA_BACKUP_CODES_CREATED",
        user_id=current_user.id,
        status="success",
        severity="info",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        location=None,
        message="New 2FA backup codes generated.",
        extra={"count": len(raw_codes)}
    )

    # Store raw in session temporarily to show in modal
    session['backup_codes'] = raw_codes
    return redirect(url_for('security'))


@app.route('/download_backup_codes')
@login_required
def download_backup_codes():
    raw_codes = session.get('backup_codes')
    if not raw_codes:
        flash("No backup codes available. Please generate them first.", "warning")
        return redirect(url_for('security'))

    content = "\n".join(raw_codes)
    response = make_response(content)
    response.headers["Content-Disposition"] = "attachment; filename=backup_codes.txt"
    response.mimetype = "text/plain"
    return response


@app.route('/complete_backup_login')
def complete_backup_login():
    user_id = session.pop('pre_2fa_user_id', None)
    if not user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for('login'))

    login_user(user)
    session['last_active'] = datetime.utcnow().isoformat()
    session.pop('bypass_security', None)

    # Add audit log / known device if needed
    ...

    flash("Logged in using backup code. Some restrictions were bypassed.", "info")
    return redirect(url_for('profile'))

@app.route('/use_backup_code', methods=['POST'])
def use_backup_code():
    code = request.form.get('backup_code', '').strip()
    user_id = session.get('pre_2fa_user_id') or session.get('backup_user_id')
    if not user_id:
        flash("Session expired. Please try logging in again.", "warning")
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    if user.backup_codes:
        codes = user.backup_codes.splitlines()
        for hashed in codes:
            if check_password_hash(hashed, code):
                # ✅ Consume the code
                codes.remove(hashed)
                user.backup_codes = "\n".join(codes) if codes else None
                db.session.commit()

                # ✅ Bypass security locks
                session['bypass_security'] = True

                # Remove block triggers
                session.pop('pre_2fa_user_id', None)
                session.pop('backup_user_id', None)

                flash("Backup code accepted. Please continue logging in.", "info")
                return redirect(url_for('login'))

    flash("Invalid or used backup code.", "danger")
    return redirect(url_for('login'))


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

        # ---- Fraud check before sending registration OTP ----
        ip, _, _ = get_ip_and_location()
        user_agent = request.headers.get('User-Agent')
        threshold = int(os.getenv('FRAUD_THRESHOLD', '75'))
        action = (os.getenv('FRAUD_FAIL_ACTION', 'step_up') or 'step_up').lower()

        risk = check_fraud_risk(email=email, ip=ip, user_agent=user_agent)

        # (Optional dev visibility)
        if app.debug:
            flash(f"[DEV] Registration fraud score={risk.get('score')} risky={risk.get('risky')}", "info")

        if risk.get('score', 0) >= threshold or risk.get('risky'):
            if action == 'block':
                flash("We couldn't proceed with this registration from your network. Please try again later.", "danger")
                return redirect(url_for('register_email'))
            # action == step_up → just continue to generate/send the OTP as usual

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
            old_email = current_user.email
            current_user.email = form.new_email.data.strip().lower()
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

        # Check password
        if not check_password_hash(user.password, form.password.data):
            flash("Incorrect password.", "danger")
            return redirect(url_for('delete_account'))

        # Check security answer
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
@role_required(3)
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
@role_required(3)
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

@app.route("/admin/overview")
# @login_required
# @role_required(3)
def admin_overview():
    now = datetime.utcnow()
    start_24h = now - timedelta(hours=24)
    start_7d  = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)

    # --- Users / growth ---
    try:
        total_users = db.session.query(func.count(User.id)).scalar() or 0
        all_users = User.query.order_by(desc(User.id)).limit(100).all()
    except Exception:
        total_users, all_users = 0, []

    # New signups (24h); tolerate missing columns
    try:
        new_signups = db.session.query(func.count(User.id))\
            .filter(User.created_at >= start_24h).scalar() or 0
        recent_users = User.query.filter(User.created_at >= start_24h)\
            .order_by(desc(User.created_at)).limit(20).all()
    except Exception:
        new_signups, recent_users = 0, []

    try:
        deactivated_users = User.query.filter_by(is_active=False).all()
        deactivated_accounts = len(deactivated_users)
    except Exception:
        deactivated_users, deactivated_accounts = [], 0

    # --- Distinct logins per day (7d) ---
    rows = (
        db.session.query(
            func.date(LoginAuditLog.timestamp).label('day'),
            func.count(distinct(LoginAuditLog.user_id)).label('uu')
        )
        .filter(LoginAuditLog.success.is_(True),
                LoginAuditLog.timestamp >= start_7d)
        .group_by(func.date(LoginAuditLog.timestamp))
        .order_by(func.date(LoginAuditLog.timestamp))
        .all()
    )
    days = [(start_7d + timedelta(days=i)).date() for i in range(7)]
    by_day = {r.day: int(r.uu) for r in rows}
    daily_active_labels = [d.isoformat() for d in days]
    daily_active_values = [by_day.get(d, 0) for d in days]
    distinct_logins_today = daily_active_values[-1] if daily_active_values else 0
    daily_active = list(zip(daily_active_labels, daily_active_values))

    # --- Success / Failure (24h) + lists ---
    successful_logins_24h = db.session.query(func.count(LoginAuditLog.id))\
        .filter(LoginAuditLog.success.is_(True),
                LoginAuditLog.timestamp >= start_24h).scalar() or 0
    failed_logins_24h = db.session.query(func.count(LoginAuditLog.id))\
        .filter(LoginAuditLog.success.is_(False),
                LoginAuditLog.timestamp >= start_24h).scalar() or 0

    recent_successful_logins = LoginAuditLog.query\
        .filter(LoginAuditLog.success.is_(True),
                LoginAuditLog.timestamp >= start_24h)\
        .order_by(desc(LoginAuditLog.timestamp)).limit(15).all()
    recent_failed_logins = LoginAuditLog.query\
        .filter(LoginAuditLog.success.is_(False),
                LoginAuditLog.timestamp >= start_24h)\
        .order_by(desc(LoginAuditLog.timestamp)).limit(15).all()

    # --- Success rate, unique IPs (24h) ---
    total_24h = successful_logins_24h + failed_logins_24h
    success_rate_24h = round((successful_logins_24h / total_24h) * 100, 1) if total_24h else 0.0
    unique_ips_24h = db.session.query(func.count(distinct(LoginAuditLog.ip_address)))\
        .filter(LoginAuditLog.timestamp >= start_24h).scalar() or 0

    # --- Top failed IPs (24h) ---
    top_failed_ips_q = db.session.query(
            LoginAuditLog.ip_address,
            func.count(LoginAuditLog.id).label("cnt")
        )\
        .filter(LoginAuditLog.success.is_(False),
                LoginAuditLog.timestamp >= start_24h,
                LoginAuditLog.ip_address.isnot(None))\
        .group_by(LoginAuditLog.ip_address)\
        .order_by(desc("cnt")).limit(5).all()
    top_failed_ips = [(ip or "Unknown", int(cnt)) for ip, cnt in top_failed_ips_q]

    # --- Peak login hour (7d, successes only) ---
    hour_counts = db.session.query(
            func.hour(LoginAuditLog.timestamp).label('h'),
            func.count().label('c')
        )\
        .filter(LoginAuditLog.success.is_(True),
                LoginAuditLog.timestamp >= start_7d)\
        .group_by('h').all()
    peak_hour = max(hour_counts, key=lambda r: r.c).h if hour_counts else None
    peak_hour_count = max((r.c for r in hour_counts), default=0)
    peak_labels = list(range(24))
    hour_map = {int(h): int(c) for h, c in hour_counts}
    peak_values = [hour_map.get(h, 0) for h in peak_labels]

    # --- Top countries (24h) from location string "Country, Region" ---
    loc_rows = db.session.query(LoginAuditLog.location)\
        .filter(LoginAuditLog.timestamp >= start_24h).all()
    countries = []
    for (loc,) in loc_rows:
        if not loc:
            countries.append('Unknown')
        else:
            countries.append((loc.split(',')[0] or '').strip() or 'Unknown')
    top_countries_24h = Counter(countries).most_common(5)

    # --- Admin/Security actions (24h) ---
    try:
        admin_actions_24h = db.session.query(
                SystemAuditLog.action_type,
                func.count(SystemAuditLog.id)
            )\
            .filter(SystemAuditLog.timestamp >= start_24h)\
            .group_by(SystemAuditLog.action_type)\
            .order_by(func.count(SystemAuditLog.id).desc())\
            .limit(5).all()
    except Exception:
        admin_actions_24h = []

    # --- Simple spike detector (failed: current hour vs previous hour) ---
    start_curr = now - timedelta(hours=1)
    start_prev = now - timedelta(hours=2)
    failed_curr = db.session.query(func.count(LoginAuditLog.id))\
        .filter(LoginAuditLog.success.is_(False),
                LoginAuditLog.timestamp >= start_curr).scalar() or 0
    failed_prev = db.session.query(func.count(LoginAuditLog.id))\
        .filter(LoginAuditLog.success.is_(False),
                LoginAuditLog.timestamp >= start_prev,
                LoginAuditLog.timestamp < start_curr).scalar() or 0
    spike_delta_pct = ((failed_curr - failed_prev) / failed_prev * 100.0) if failed_prev else (100.0 if failed_curr else 0.0)
    spike_alert = failed_curr >= max(5, int(failed_prev * 1.5))

    return render_template(
        "admin_overview.html",
        total_users=total_users, all_users=all_users,
        new_signups=new_signups, recent_users=recent_users,
        deactivated_users=deactivated_users, deactivated_accounts=deactivated_accounts,
        daily_active=daily_active, distinct_logins_today=distinct_logins_today,
        successful_logins_24h=successful_logins_24h, failed_logins_24h=failed_logins_24h,
        success_rate_24h=success_rate_24h, unique_ips_24h=unique_ips_24h,
        recent_successful_logins=recent_successful_logins, recent_failed_logins=recent_failed_logins,
        top_failed_ips=top_failed_ips,
        peak_hour=peak_hour, peak_hour_count=peak_hour_count,
        peak_labels=peak_labels, peak_values=peak_values,
        top_countries_24h=top_countries_24h,
        admin_actions_24h=admin_actions_24h,
        spike_alert=spike_alert, spike_delta_pct=round(spike_delta_pct, 1),
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
    user.is_active = not user.is_active
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
@login_required
def security_dashboard():
    # ---------------- Login Audit Logs (with filters) ----------------
    login_query = LoginAuditLog.query

    email = request.args.get('email', '').strip()
    if email:
        login_query = login_query.filter(LoginAuditLog.email == email)

    login_user_id = request.args.get('login_user_id', '').strip()
    if login_user_id:
        login_query = login_query.filter(LoginAuditLog.user_id == login_user_id)

    success = request.args.get('success', '').strip()
    if success in ('0', '1'):
        login_query = login_query.filter(LoginAuditLog.success == (success == '1'))

    location = request.args.get('location', '').strip()
    if location:
        login_query = login_query.filter(LoginAuditLog.location == location)

    logs = login_query.order_by(LoginAuditLog.timestamp.desc()).limit(50).all()

    # ---------------- Known Devices (no filters in UI) ----------------
    devices = KnownDevice.query.order_by(KnownDevice.last_seen.desc()).limit(50).all()

    # ---------------- System Audit Logs (with filters) ----------------
    audit_query = SystemAuditLog.query

    user_id = request.args.get('user_id', '').strip()
    if user_id:
        audit_query = audit_query.filter(SystemAuditLog.user_id == user_id)

    action_type = request.args.get('action_type', '').strip()
    if action_type:
        audit_query = audit_query.filter(SystemAuditLog.action_type == action_type)

    category = request.args.get('category', '').strip()
    if category:
        audit_query = audit_query.filter(SystemAuditLog.category == category)

    log_level = request.args.get('log_level', '').strip()
    if log_level:
        audit_query = audit_query.filter(SystemAuditLog.log_level == log_level)

    ip = request.args.get('ip', '').strip()
    if ip:
        audit_query = audit_query.filter(SystemAuditLog.ip_address.contains(ip))

    endpoint = request.args.get('endpoint', '').strip()
    if endpoint:
        audit_query = audit_query.filter(SystemAuditLog.endpoint.contains(endpoint))

    # --- Date range (FIXED) ---
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()

    start_dt, end_dt = None, None  # ensure defined for debugging

    if start_date:
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            audit_query = audit_query.filter(SystemAuditLog.timestamp >= start_dt)
        except ValueError:
            # Invalid date format; ignore
            pass

    if end_date:
        try:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
            # include full end date up to 23:59:59
            end_dt = end_dt.replace(hour=23, minute=59, second=59)
            audit_query = audit_query.filter(SystemAuditLog.timestamp <= end_dt)
        except ValueError:
            # Invalid date format; ignore
            pass

    audit_logs = audit_query.order_by(SystemAuditLog.timestamp.desc()).limit(100).all()

    # ---------------- Dropdown Data (for your template) ----------------
    # Distinct values for Login Logs filters
    emails = [e for (e,) in db.session.query(LoginAuditLog.email).distinct()]
    locations = [loc for (loc,) in db.session.query(LoginAuditLog.location).distinct()]

    # User IDs: use a union so the single 'user_ids' list supports both sections
    user_ids_login = {uid for (uid,) in db.session.query(LoginAuditLog.user_id).distinct() if uid is not None}
    user_ids_audit = {uid for (uid,) in db.session.query(SystemAuditLog.user_id).distinct() if uid is not None}
    user_ids = sorted(user_ids_login.union(user_ids_audit))

    # Distinct values for System Audit Log filters
    action_types = [a for (a,) in db.session.query(SystemAuditLog.action_type).distinct()]
    categories = [c for (c,) in db.session.query(SystemAuditLog.category).distinct()]

    return render_template(
        'security_dashboard.html',
        # Tables
        logs=logs,
        devices=devices,
        audit_logs=audit_logs,
        # Dropdown data
        emails=emails,
        user_ids=user_ids,
        action_types=action_types,
        categories=categories,
        locations=locations
    )

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

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
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


if __name__ == '__main__':
    app.run(debug=True)