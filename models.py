from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_staff = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)
    is_locked = db.Column(db.Boolean, default=False)
