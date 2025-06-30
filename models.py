from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from functools import wraps
from flask import abort
from flask_login import current_user

db = SQLAlchemy()

# User model with 'role' column instead of is_staff
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # roles: admin, staff, user

class LoginAuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
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

# Role hierarchy: user < staff < admin
ROLE_HIERARCHY = {
    'user': 1,
    'staff': 2,
    'admin': 3
}

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)  # or redirect to login
            user_role = current_user.role
            user_level = ROLE_HIERARCHY.get(user_role, 0)
            allowed_levels = [ROLE_HIERARCHY.get(role, 0) for role in allowed_roles]
            # User must have role level >= any of the allowed roles' levels
            if any(user_level >= level for level in allowed_levels):
                return f(*args, **kwargs)
            else:
                abort(403)
        return decorated_function
    return decorator
