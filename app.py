from flask import Flask, render_template
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

# RENFRED PLEASE FILL IN
# RENFRED PLEASE FILL IN
# RENFRED PLEASE FILL IN
# RENFRED PLEASE FILL IN
# RENFRED PLEASE FILL IN
# RENFRED PLEASE FILL IN
# RENFRED PLEASE FILL IN
# RENFRED PLEASE FILL IN
# RENFRED PLEASE FILL IN
DATABASE_URL = "mysql+mysqlconnector://username:password@localhost:3306/your_database"

engine = create_engine(DATABASE_URL, echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/product')
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
