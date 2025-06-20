from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User
from forms import LoginForm, OTPForm, ChangePasswordForm, Toggle2FAForm
from datetime import datetime, timedelta
import random
from flask_mail import Mail, Message

app = Flask(__name__)
# … your existing config …
app.config.update({
  # example using Gmail SMTP; adapt to your provider
  'MAIL_SERVER':   'smtp.gmail.com',
  'MAIL_PORT':     587,
  'MAIL_USE_TLS':  True,
  'MAIL_USERNAME': 'usertestuser919@gmail.com',
  'MAIL_PASSWORD': 'lyqv gadp uqqo jymb',
  'MAIL_DEFAULT_SENDER': 'No Reply <testusertest919+no-reply@gmail.com>'
})

mail = Mail(app)
# Config
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mysql+mysqlconnector://securityprojuser:Mysql123'
    '@127.0.0.1:3306/securityproject'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfGqGMrAAAAAIKvHI9aL0ZD-8xbP2LhPRSZPp3n'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LfGqGMrAAAAAOwHdibEUSMjteGZjVlBo72hjJx9'
app.config['WTF_CSRF_ENABLED'] = True

# -- 1) Create DB (if needed) and switch to it
# CREATE DATABASE IF NOT EXISTS securityproject;
# USE securityproject;
#
# -- 2) Drop & re-create the user table from scratch
# DROP TABLE IF EXISTS `user`;
# CREATE TABLE `user` (
#   `id`                 INT           NOT NULL AUTO_INCREMENT,
#   `username`           VARCHAR(50)   NOT NULL UNIQUE,
#   `email`              VARCHAR(100)  NOT NULL UNIQUE,
#   `password`           VARCHAR(255)  NOT NULL,
#   `is_staff`           BOOLEAN       NOT NULL DEFAULT FALSE,
#
#   -- account lockout
#   `failed_attempts`    INT           NOT NULL DEFAULT 0,
#   `last_failed_login`  DATETIME      NULL,
#   `is_locked`          BOOLEAN       NOT NULL DEFAULT FALSE,
#
#   -- email-OTP 2FA
#   `two_factor_enabled` BOOLEAN       NOT NULL DEFAULT TRUE,
#   `otp_code`           VARCHAR(6)    NULL,
#   `otp_expiry`         DATETIME      NULL,
#
#   PRIMARY KEY (`id`)
# ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

# from werkzeug.security import generate_password_hash
# print(generate_password_hash("test123"))
# print(generate_password_hash("test123"))
# Session timeout settings
app.permanent_session_lifetime = timedelta(seconds=30)

# Secure cookies
app.config.update({
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax"
})

db.init_app(app)

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def on_unauthorized():
    if session.get('last_active'):
        return redirect(url_for('login', message='timeout'))
    return redirect(url_for('login'))


@app.before_request
def check_session_timeout():
    if current_user.is_authenticated:
        now = datetime.utcnow()
        last_active = session.get('last_active')
        if last_active:
            last_active = datetime.fromisoformat(last_active)
            if now - last_active > timedelta(seconds=30):
                logout_user()
                session.clear()
                return redirect(url_for('login', message='timeout'))
        session['last_active'] = now.isoformat()

@app.route('/toggle_2fa', methods=['POST'])
@login_required
def toggle_2fa():
    form = Toggle2FAForm()
    if form.validate_on_submit():
        current_user.two_factor_enabled = not current_user.two_factor_enabled
        db.session.commit()
    return redirect(url_for('profile'))

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If they’re already logged in, send them home
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form  = LoginForm()
    error = None

    # Lockout policy
    LOCK_DURATION = timedelta(seconds=20)
    MAX_ATTEMPTS  = 3

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            # Account lockout
            if user.is_locked:
                last = user.last_failed_login
                if last and datetime.utcnow() - last >= LOCK_DURATION:
                    user.failed_attempts = 0
                    user.is_locked       = False
                    db.session.commit()
                else:
                    error = "Account locked. Please try again later."
                    return render_template('login.html',
                                           form=form, error=error)

            # Password validation
            if check_password_hash(user.password, form.password.data):
                # Email‐OTP 2FA
                if user.two_factor_enabled:
                    code = f"{random.randint(0, 999999):06d}"
                    user.otp_code   = code
                    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                    db.session.commit()

                    msg = Message(
                        subject="Your One-Time Login Code",
                        recipients=[user.email],
                        body=f"Hello {user.username},\n\nYour login code is: {code}\n\n"
                             "It expires in 5 minutes."
                    )
                    mail.send(msg)

                    session['pre_2fa_user_id'] = user.id
                    return redirect(url_for('two_factor'))

                # No 2FA: complete login
                login_user(user)
                session['last_active'] = datetime.utcnow().isoformat()
                user.failed_attempts   = 0
                db.session.commit()
                return redirect(url_for('profile'))

            # Wrong password
            user.failed_attempts   += 1
            user.last_failed_login  = datetime.utcnow()
            if user.failed_attempts >= MAX_ATTEMPTS:
                user.is_locked = True
            db.session.commit()
            error = 'Incorrect email or password.'
        else:
            error = 'Email not found.'

    return render_template('login.html',
                           form=form,
                           error=error,
                           message=request.args.get('message'))

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

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    form = OTPForm()
    error = None

    if form.validate_on_submit():
        token = form.token.data.strip()
        if not user.otp_expiry or datetime.utcnow() > user.otp_expiry:
            error = 'Code expired. Please log in again.'
            session.pop('pre_2fa_user_id', None)
        elif token != user.otp_code:
            error = 'Invalid code. Please try again.'
        else:
            # Successful 2FA
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            session['last_active'] = datetime.utcnow().isoformat()
            user.failed_attempts   = 0
            user.otp_code          = None
            user.otp_expiry        = None
            db.session.commit()
            return redirect(url_for('profile'))

    resent = bool(request.args.get('resent'))

    return render_template('two_factor.html', form=form, error=error, resent=resent)

@app.route('/resend_code')
def resend_code():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    # generate & store new code
    code = f"{random.randint(0, 999999):06d}"
    user.otp_code   = code
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    # email it out
    msg = Message(
        subject="Your One-Time Login Code (Resent)",
        recipients=[user.email],
        body=(
            f"Hello {user.username},\n\n"
            f"Your new login code is: {code}\n\n"
            "It expires in 5 minutes."
        )
    )
    mail.send(msg)

    # redirect back with a flag
    return redirect(url_for('two_factor', resent=1))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    toggle_form = Toggle2FAForm()
    return render_template('profile.html',
                           toggle_form=toggle_form)

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

if __name__ == '__main__':
    app.run(debug=True)


