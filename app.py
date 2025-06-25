from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from models import db, User


app = Flask(__name__)

# ✅ Config for Flask-SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://securityprojuser:Mysql123@127.0.0.1:3306/securityproject'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret'
db.init_app(app)

# -- Step 1: Create the database if not already present
# CREATE DATABASE IF NOT EXISTS securityproject;
# USE securityproject;
#
# -- Step 3: Create roles table
# CREATE TABLE `roles` (
#   id   INT AUTO_INCREMENT PRIMARY KEY,
#   name VARCHAR(20) UNIQUE NOT NULL
# ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
#
# -- Step 4: Insert default roles
# INSERT INTO `roles` (name) VALUES
#   ('user'),
#   ('staff'),
#   ('admin');
#
# -- Step 5: Create user table and link role_id to roles table
# CREATE TABLE `user` (
#   id                 INT AUTO_INCREMENT PRIMARY KEY,
#   username           VARCHAR(50)  NOT NULL UNIQUE,
#   email              VARCHAR(100) NOT NULL UNIQUE,
#   password           VARCHAR(255) NOT NULL,
#
#   role_id            INT NOT NULL DEFAULT 1,
#   FOREIGN KEY (role_id) REFERENCES `roles`(id),
#
#   failed_attempts    INT          NOT NULL DEFAULT 0,
#   last_failed_login  DATETIME     NULL,
#   is_locked          BOOLEAN      NOT NULL DEFAULT FALSE,
#   two_factor_enabled BOOLEAN      NOT NULL DEFAULT TRUE,
#   otp_code           VARCHAR(6),
#   otp_expiry         DATETIME
# ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
#
# -- Step 6: Insert a sample user (password = 'test123', role = 'user')
# -- Replace the hash below with your generated password hash if needed
# INSERT INTO `user` (username, email, password, role_id)
# VALUES (
#   'test',
#   'test@gmail.com',
#   'hashed password',
# -- print(generate_password_hash('test123'))
#   1  -- user role
# );


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ Routes
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

        if not user:
            error = 'Email not found. Please try again.'
        elif not check_password_hash(user.password, password):
            error = 'Incorrect password. Please try again.'
        else:
            login_user(user)
            return redirect(url_for('profile'))

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

if __name__ == '__main__':
    app.run(debug=True)
