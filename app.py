from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from hashlib import sha256
from datetime import datetime, timedelta
import requests
from models import db, User, SystemAuditLog, KnownDevice, role_required, LoginAuditLog

app = Flask(__name__)

# Config
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://securityprojuser:Mysql123@127.0.0.1:3306/securityproject'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret'
db.init_app(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# System Audit Log
def log_system_action(user_id, action_type, description=None):
    ip, location = get_ip_and_location()
    user_agent = request.headers.get('User-Agent')

    log = SystemAuditLog(
        user_id=user_id,
        action_type=action_type,
        description=description,
        ip_address=ip,
        user_agent=user_agent,
        location=location
    )
    db.session.add(log)
    db.session.commit()



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Device hash generator for device recognition
def generate_device_hash(ip, user_agent):
    return sha256(f"{ip}_{user_agent}".encode()).hexdigest()

# Get public IP and location using ipify + ipapi
def get_ip_and_location():
    try:
        ip_response = requests.get('https://api.ipify.org?format=json', timeout=3)
        ip = ip_response.json().get('ip')

        loc_response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=3)
        loc_data = loc_response.json()

        city = loc_data.get('city', '')
        region = loc_data.get('region', '')
        country = loc_data.get('country_name', '')

        location = ', '.join(filter(None, [city, region, country]))
        return ip, location
    except Exception as e:
        print("GeoIP fetch failed:", e)
        return "Unknown", "Unknown"

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
        user_id = user.id if user else None

        # Get IP and location
        ip, location = get_ip_and_location()
        if user and not user.is_active:
            error = 'This account is deactivated.'
            return render_template('login.html', error=error)

        if user and check_password_hash(user.password, password):
            login_user(user)
            success = True

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
                    user_agent=user_agent,
                    location=location
                )
                db.session.add(known_device)

        # Log the login attempt
        log = LoginAuditLog(
            user_id=user_id,
            email=email,
            success=success,
            ip_address=ip,
            user_agent=request.headers.get('User-Agent'),
            location=location
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

@app.route('/admin/overview')
@login_required
@role_required(3)
def admin_overview():
    utc_now = datetime.utcnow()
    day_ago = utc_now - timedelta(days=1)

    total_users = User.query.count()
    new_signups = User.query.filter(User.created_at >= day_ago).count()
    successful_logins_24h = LoginAuditLog.query.filter(
        LoginAuditLog.timestamp >= day_ago,
        LoginAuditLog.success == True
    ).count()

    failed_logins_24h = LoginAuditLog.query.filter(
        LoginAuditLog.timestamp >= day_ago,
        LoginAuditLog.success == False
    ).count()

    deactivated_accounts = User.query.filter_by(is_active=False).count()
    active_today = LoginAuditLog.query.filter(LoginAuditLog.timestamp >= day_ago, LoginAuditLog.success == True).distinct(LoginAuditLog.user_id).count()

    return render_template(
        'admin_overview.html',
        total_users=total_users,
        new_signups=new_signups,
        successful_logins_24h=successful_logins_24h,
        failed_logins_24h=failed_logins_24h,
        active_today=active_today,
        deactivated_accounts=deactivated_accounts
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
        flash('New user added.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('admin_user_form.html', action='Add')

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required(3)
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role_id = int(request.form['role_id'])
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('User updated.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('admin_user_form.html', action='Edit', user=user)

@app.route('/admin/users')
@login_required
@role_required(3)
def admin_manage_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/<int:user_id>/toggle')
@login_required
@role_required(3)
def toggle_user_activation(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"{user.username} is now {'active' if user.is_active else 'deactivated'}.", "info")
    return redirect(url_for('manage_users'))


@app.route('/admin/security_dashboard')
@login_required
@role_required(3)
def security_dashboard():
    logs_query = LoginAuditLog.query

    # Get filter values from request
    email_filter = request.args.get('email')
    location_filter = request.args.get('location')
    success_filter = request.args.get('success')

    if email_filter:
        logs_query = logs_query.filter(LoginAuditLog.email == email_filter)
    if location_filter:
        logs_query = logs_query.filter(LoginAuditLog.location == location_filter)
    if success_filter in ['0', '1']:
        logs_query = logs_query.filter(LoginAuditLog.success == bool(int(success_filter)))

    logs = logs_query.order_by(LoginAuditLog.timestamp.desc()).limit(50).all()
    devices = KnownDevice.query.order_by(KnownDevice.last_seen.desc()).limit(50).all()

    # ✨ Fetch unique filter values
    emails = [e[0] for e in db.session.query(LoginAuditLog.email).distinct().all()]
    locations = [l[0] for l in db.session.query(LoginAuditLog.location).distinct().all()]

    return render_template('security_dashboard.html', logs=logs, devices=devices,
                           emails=emails, locations=locations)

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

if __name__ == '__main__':
    app.run(debug=True)
