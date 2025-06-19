from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User
from forms import LoginForm, ChangePasswordForm
from datetime import datetime, timedelta

app = Flask(__name__)

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

# CREATE TABLE user (
#     id INT PRIMARY KEY AUTO_INCREMENT,
#     username VARCHAR(50) NOT NULL UNIQUE,
#     email VARCHAR(100) NOT NULL UNIQUE,
#     password VARCHAR(255) NOT NULL,
#     is_staff BOOLEAN DEFAULT FALSE
# );
# INSERT INTO user (username, email, password, is_staff)
# VALUES ('test', 'test@gmail.com', 'test123', FALSE);
# ALTER TABLE user DROP COLUMN failed_attempts;
# ALTER TABLE user DROP COLUMN last_failed_login;
# ALTER TABLE user DROP COLUMN is_locked;
# from werkzeug.security import generate_password_hash
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

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    LOCK_DURATION = timedelta(seconds=20)
    MAX_ATTEMPTS = 3
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if user.is_locked:
                if (user.last_failed_login and
                    datetime.utcnow() - user.last_failed_login >= LOCK_DURATION):
                    user.failed_attempts = 0
                    user.is_locked = False
                    db.session.commit()
                else:
                    error = "Your account is temporarily locked. Please try again later."
                    return render_template('login.html', form=form, error=error)
            if check_password_hash(user.password, password):
                login_user(user)
                session['last_active'] = datetime.utcnow().isoformat()
                user.failed_attempts = 0
                db.session.commit()
                return redirect(url_for('profile'))
            else:
                user.failed_attempts += 1
                user.last_failed_login = datetime.utcnow()
                if user.failed_attempts >= MAX_ATTEMPTS:
                    user.is_locked = True
                db.session.commit()
                error = 'Incorrect password or email.'
        else:
            error = 'Email not found.'
    message = request.args.get('message')
    return render_template('login.html', form=form, error=error, message=message)

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

@app.route('/register')
def register():
    return render_template('register.html')

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

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True)


