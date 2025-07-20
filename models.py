from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import PickleType, DateTime
from datetime import datetime
from functools import wraps
from flask import abort
from flask_login import current_user

db = SQLAlchemy()


class Role(db.Model):
    __tablename__ = 'roles'
    id   = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    users = db.relationship('User', back_populates='role')

class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id                 = db.Column(db.Integer, primary_key=True)
    username           = db.Column(db.String(50), unique=True, nullable=False)
    email              = db.Column(db.String(100), unique=True, nullable=False)
    password           = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    birthdate = db.Column(db.Date, nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    role = db.relationship('Role', back_populates='users')

    # Lockout & 2FA
    failed_attempts    = db.Column(db.Integer, default=0)
    last_failed_login  = db.Column(db.DateTime, nullable=True)
    is_locked          = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=True)
    otp_code           = db.Column(db.String(512), nullable=True)
    otp_expiry         = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    preferred_2fa = db.Column(db.String(10), default='email')
    region_lock_enabled = db.Column(db.Boolean, default=False)
    last_country = db.Column(db.String(64))
    signup_method = db.Column(db.String(20), nullable=False, default='email')


    password_history = db.Column(PickleType, default=list)
    password_last_changed = db.Column(DateTime, default=datetime.utcnow)

    security_question = db.Column(db.String(255), nullable=True)
    security_answer_hash = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    #Audit
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginAuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)
    email = db.Column(db.String(100))
    success = db.Column(db.Boolean)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    location = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())

class SystemAuditLog(db.Model):
    __tablename__ = 'system_audit_log'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    role_id_at_action_time = db.Column(db.Integer, nullable=True)
    request_id = db.Column(db.String(64), nullable=True)
    log_level = db.Column(db.String(20), default='INFO')           # INFO, WARNING, ERROR
    category = db.Column(db.String(50), default='GENERAL')         # AUTH, ADMIN, PROFILE, SECURITY, etc.
    endpoint = db.Column(db.String(255))                           # Flask route
    http_method = db.Column(db.String(10))                         # GET, POST, etc.
    session_id = db.Column(db.String(64), nullable=True)           # Generated per session
    affected_object_id = db.Column(db.String(64), nullable=True)   # Optional: e.g., User ID being edited
    changed_fields = db.Column(db.Text, nullable=True)             # JSON or string of changes
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    location = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='system_logs')

class KnownDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    device_hash = db.Column(db.String(255))
    user_agent = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(255))
    first_seen = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    last_seen = db.Column(db.DateTime, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

# Role IDs correspond to hierarchy levels:
# 1 = user (lowest), 2 = staff, 3 = admin (highest)
ROLE_HIERARCHY = {
    1: 1,  # user
    2: 2,  # staff
    3: 3   # admin
}

def role_required(*allowed_role_ids):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)
            user_level = ROLE_HIERARCHY.get(current_user.role_id, 0)
            allowed_levels = [ROLE_HIERARCHY.get(rid, 0) for rid in allowed_role_ids]
            if any(user_level >= level for level in allowed_levels):
                return f(*args, **kwargs)
            else:
                abort(403)
        return decorated_function
    return decorator