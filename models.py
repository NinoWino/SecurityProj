from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user
from functools import wraps
from flask import abort
from datetime import datetime

db = SQLAlchemy()

# User table
class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id                 = db.Column(db.Integer, primary_key=True)
    username           = db.Column(db.String(50), unique=True, nullable=False)
    email              = db.Column(db.String(100), unique=True, nullable=False)
    password           = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    role = db.relationship('Role', back_populates='users')
    # Lockout & 2FA
    failed_attempts    = db.Column(db.Integer, default=0)
    last_failed_login  = db.Column(db.DateTime, nullable=True)
    is_locked          = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=True)
    otp_code           = db.Column(db.String(6), nullable=True)
    otp_expiry         = db.Column(db.DateTime, nullable=True)

class Role(db.Model):
    __tablename__ = 'roles'
    id   = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)

    users = db.relationship('User', back_populates='role')

# Login audit logs
class LoginAuditLog(db.Model):
    __tablename__ = 'login_audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    email = db.Column(db.String(100), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Known devices per user
class KnownDevice(db.Model):
    __tablename__ = 'known_device'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_hash = db.Column(db.String(255), nullable=False)
    user_agent = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

