from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash,generate_password_hash
from hashlib import sha256
from datetime import datetime
from models import db, User, LoginAuditLog, KnownDevice, role_required

app = Flask(__name__)

# -- Drop tables if they exist (order matters due to foreign keys)
# DROP TABLE IF EXISTS known_device;
# DROP TABLE IF EXISTS login_audit_log;
# DROP TABLE IF EXISTS user;
# DROP TABLE IF EXISTS roles;
#
# -- Step 1: Create roles table
# CREATE TABLE roles (
#   id INT AUTO_INCREMENT PRIMARY KEY,
#   name VARCHAR(20) UNIQUE NOT NULL
# ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
#
# -- Step 2: Insert default roles
# INSERT INTO roles (name) VALUES
#   ('user'),
#   ('staff'),
#   ('admin');
#
# -- Step 3: Create user table with role_id as foreign key
# CREATE TABLE user (
#   id INT AUTO_INCREMENT PRIMARY KEY,
#   username VARCHAR(50) NOT NULL UNIQUE,
#   email VARCHAR(100) NOT NULL UNIQUE,
#   password VARCHAR(255) NOT NULL,
#
#   role_id INT NOT NULL DEFAULT 1,
#   FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT,
#
#   failed_attempts INT NOT NULL DEFAULT 0,
#   last_failed_login DATETIME NULL,
#   is_locked BOOLEAN NOT NULL DEFAULT FALSE,
#   two_factor_enabled BOOLEAN NOT NULL DEFAULT TRUE,
#   otp_code VARCHAR(6),
#   otp_expiry DATETIME
# ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
#
# -- Step 4: Create login audit log table
# CREATE TABLE login_audit_log (
#   id INT AUTO_INCREMENT PRIMARY KEY,
#   user_id INT,
#   email VARCHAR(100),
#   success BOOLEAN,
#   ip_address VARCHAR(45),
#   user_agent TEXT,
#   timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#   FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
# );
#
# -- Step 5: Create known device table
# CREATE TABLE known_device (
#   id INT AUTO_INCREMENT PRIMARY KEY,
#   user_id INT,
#   device_hash VARCHAR(255),
#   user_agent TEXT,
#   ip_address VARCHAR(45),
#   first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#   last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
#   FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
# );
#
# -- Step 6: Insert users with role_id references
# INSERT INTO user (username, email, password, role_id)
# VALUES
# ('test1', 'test1@gmail.com', 'scrypt:32768:8:1$Wke2fNh5abRTHWl9$80d6183011a206f08f60b717a0e824d167227dd8495e6622857a8cb5cea518bf02045c4ffa17d3bb533c3673fe0bf5cf11842b8278d756ee0575e4a0ddda6265', 1),
# ('test2', 'test2@gmail.com', 'scrypt:32768:8:1$Wke2fNh5abRTHWl9$80d6183011a206f08f60b717a0e824d167227dd8495e6622857a8cb5cea518bf02045c4ffa17d3bb533c3673fe0bf5cf11842b8278d756ee0575e4a0ddda6265', 1),
# ('test3', 'test3@gmail.com', 'scrypt:32768:8:1$Wke2fNh5abRTHWl9$80d6183011a206f08f60b717a0e824d167227dd8495e6622857a8cb5cea518bf02045c4ffa17d3bb533c3673fe0bf5cf11842b8278d756ee0575e4a0ddda6265', 2),
# ('test4', 'test4@gmail.com', 'scrypt:32768:8:1$Wke2fNh5abRTHWl9$80d6183011a206f08f60b717a0e824d167227dd8495e6622857a8cb5cea518bf02045c4ffa17d3bb533c3673fe0bf5cf11842b8278d756ee0575e4a0ddda6265', 3);




# Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://securityprojuser:Mysql123@127.0.0.1:3306/securityproject'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret'
db.init_app(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Device hash generator for device recognition
def generate_device_hash(ip, user_agent):
    return sha256(f"{ip}_{user_agent}".encode()).hexdigest()

# Routes

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        success = False
        user_id = user.id if user else None  # 👈 Set user_id early

        if user and check_password_hash(user.password, password):
            login_user(user)
            success = True

            # Device recognition
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            device_hash = generate_device_hash(ip, user_agent)

            known_device = KnownDevice.query.filter_by(user_id=user.id, device_hash=device_hash).first()
            if known_device:
                known_device.last_seen = datetime.utcnow()
            else:
                known_device = KnownDevice(
                    user_id=user.id,
                    device_hash=device_hash,
                    ip_address=ip,
                    user_agent=user_agent
                )
                db.session.add(known_device)

        # ✅ Always log attempt regardless of outcome
        log = LoginAuditLog(
            user_id=user_id,
            email=email,
            success=success,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(log)
        db.session.commit()

        if success:
            return redirect(url_for('profile'))
        else:
            error = 'Invalid email or password.'

    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    return render_template("profile.html")

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

# Role-based dashboards

@app.route('/user')
@login_required
@role_required(1, 2, 3)  # user, staff, admin
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/staff')
@login_required
@role_required(2, 3)  # staff, admin
def staff_dashboard():
    return render_template('staff_dashboard.html')

@app.route('/admin')
@login_required
@role_required(3)  # admin only
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/security')
@login_required
@role_required(3)  # admin only
def security_dashboard():
    logs = LoginAuditLog.query.order_by(LoginAuditLog.timestamp.desc()).limit(50).all()
    devices = KnownDevice.query.order_by(KnownDevice.last_seen.desc()).limit(50).all()
    return render_template('security_dashboard.html', logs=logs, devices=devices)

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

if __name__ == '__main__':
    app.run(debug=True)
