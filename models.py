from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

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
    totp_secret = db.Column(db.String(32), nullable=True)
    preferred_2fa = db.Column(db.String(10), default='email')
    region_lock_enabled = db.Column(db.Boolean, default=False)
    last_country = db.Column(db.String(64))

class Role(db.Model):
    __tablename__ = 'roles'
    id   = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)

    users = db.relationship('User', back_populates='role')