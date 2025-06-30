from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from functools import wraps
from flask import abort
from flask_login import current_user

db = SQLAlchemy()

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='RESTRICT'), nullable=False, default=1)
    role = db.relationship('Role', backref='users')

    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    two_factor_enabled = db.Column(db.Boolean, nullable=False, default=True)
    otp_code = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)

class LoginAuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)
    email = db.Column(db.String(100))
    success = db.Column(db.Boolean)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())


class KnownDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    device_hash = db.Column(db.String(255))
    user_agent = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
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
