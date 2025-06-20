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

# INSERT INTO `user` (
#   username, email, password, is_staff
# )
# VALUES (
#   'test',
#   'test@gmail.com',
#   '$pbkdf2-sha256$600000$FQ63b3nGvWBqTGMArLvTFw$QnHo9VCzF7Q6qommbhrkCujk82MTO3aQr8J3MOGEi7k',
#   FALSE
# );

# from werkzeug.security import generate_password_hash
# print(generate_password_hash("test123"))

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
