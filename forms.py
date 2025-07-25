from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField , SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length ,ValidationError, Regexp , Optional
from flask_wtf.recaptcha import RecaptchaField
from wtforms import ValidationError
from wtforms.fields import TimeField
from flask_login import current_user
from zxcvbn import zxcvbn
import hashlib
import requests
from datetime import date
import ipaddress

def validate_pwned_password(field):
    sha1 = hashlib.sha1(field.data.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code != 200:
            raise ValidationError("Password breach check failed. Please try again.")
        hashes = (line.split(':') for line in response.text.splitlines())
        if any(s == suffix for s, _ in hashes):
            raise ValidationError("This password has been found in known data breaches. Please use a different one.")
    except requests.RequestException:
        raise ValidationError("Could not check password breach status. Try again later.")

# ✅ Existing Forms

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')


from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, DecimalField, TextAreaField, SubmitField
class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    description = TextAreaField('Description')
    image = FileField('Product Image', validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    submit = SubmitField('Add Product')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(
        'Current Password',
        validators=[DataRequired()]
    )
    new_password = PasswordField(
        'New Password',
        validators=[DataRequired()]
    )
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(),
            EqualTo('new_password', message='Passwords must match')
        ]
    )
    submit = SubmitField('Change Password')

    def validate_new_password(self, field):
        result = zxcvbn(field.data)
        if result['score'] < 3:
            raise ValidationError("Password is too weak. Use at least 8 characters, with uppercase, lowercase, numbers, and symbols.")
        validate_pwned_password(field)

class OTPForm(FlaskForm):
    token = StringField(
        'Enter 6-digit code',
        validators=[DataRequired(), Length(min=6, max=6)]
    )
    submit = SubmitField('Verify')

class Toggle2FAForm(FlaskForm):
    submit = SubmitField()

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

class ResetPasswordForm(FlaskForm):
    otp = StringField('OTP Code', validators=[DataRequired(), Length(min=6, max=6)])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')]
    )
    submit = SubmitField('Reset Password')

    def validate_new_password(self, field):
        result = zxcvbn(field.data)
        if result['score'] < 3:
            raise ValidationError(
                "Password is too weak. Use at least 8 characters, with uppercase, lowercase, numbers, and symbols.")
        validate_pwned_password(field)


class BirthdateForm(FlaskForm):
    birthdate = DateField(
        'Birthdate (YYYY-MM-DD)',
        format='%Y-%m-%d',
        validators=[DataRequired()]
    )
    security_question = SelectField('Security Question', choices=[
        ('pet', "What is the name of your first pet?"),
        ('movie', "What is your favorite childhood movie?"),
        ('friend', "What is your childhood best friend's first name?"),
        ('hero', "Who was your childhood hero?")
    ], validators=[DataRequired()])

    security_answer = StringField('Answer', validators=[DataRequired()])

    submit = SubmitField('Save')

    def validate_birthdate(self, field):
        today = date.today()
        bd = field.data

        # 1) No future dates
        if bd > today:
            raise ValidationError("Birthdate cannot be in the future.")

        # 2) Minimum age (e.g. 13 years)
        min_age_years = 13
        age = today.year - bd.year - ((today.month, today.day) < (bd.month, bd.day))
        if age < min_age_years:
            raise ValidationError(f"You must be at least {min_age_years} years old.")

        # 3) Optional: very old dates (e.g. >120 years ago)
        if age > 120:
            raise ValidationError("That date seems too far in the past.")


class EmailForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Next')

class RegisterDetailsForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])

    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=25, message="Username must be 3-25 characters.")
    ])

    phone = StringField('Phone Number', validators=[
        Optional(),
        Regexp(r'^\+?\d{8,15}$', message='Enter a valid phone number.')
    ])

    birthdate = DateField('Birthdate (YYYY-MM-DD)', format='%Y-%m-%d', validators=[
        DataRequired()
    ])

    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='At least 8 characters.')
    ])

    security_question = SelectField('Security Question', choices=[
        ('pet', "What is the name of your first pet?"),
        ('movie', "What is your favorite childhood movie?"),
        ('friend', "What is your childhood best friend's first name?"),
        ('hero', "Who was your childhood hero?")
    ], validators=[DataRequired()])

    security_answer = StringField('Answer', validators=[DataRequired()])

    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')

    def validate_password(self, field):
        result = zxcvbn(field.data)
        if result['score'] < 3:
            raise ValidationError("Password is too weak. Use at least 8 characters, with uppercase, lowercase, numbers, and symbols.")
        validate_pwned_password(field)

    def validate_phone(self, field):
        from models import User
        if User.query.filter_by(phone=field.data.strip()).first():
            raise ValidationError('This phone number is already in use.')

    def validate_username(self, field):
        from models import User
        if User.query.filter_by(username=field.data.strip()).first():
            raise ValidationError('Username already taken.')

class ChangeUsernameForm(FlaskForm):
    new_username = StringField('New Username', validators=[
        DataRequired(),
        Length(min=3, max=25, message="Username must be 3-25 characters.")
    ])
    submit = SubmitField('Change Username')

    def validate_new_username(self, field):
        from models import User
        user = User.query.filter_by(username=field.data).first()
        if user and user.id != current_user.id:
            raise ValidationError('Username is already taken.')

class ChangeEmailForm(FlaskForm):
    new_email = StringField('New Email', validators=[
        DataRequired(),
        Email(message="Enter a valid email.")
    ])
    submit = SubmitField('Change Email')

    def validate_new_email(self, field):
        from models import User
        user = User.query.filter_by(email=field.data).first()
        if user and user.id != current_user.id:
            raise ValidationError('Email is already registered.')

class DeleteAccountForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired()])
    submit = SubmitField('Confirm Delete')

class ForcePasswordResetForm(FlaskForm):
    old_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Update Password')

    def validate_new_password(self, field):
        result = zxcvbn(field.data)
        if result['score'] < 3:
            raise ValidationError(
                "Password is too weak. Use at least 8 characters, with uppercase, lowercase, numbers, and symbols.")
        validate_pwned_password(field)

class VerifyTOTPForm(FlaskForm):
    token = StringField('Authentication Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

class LoginRestrictionForm(FlaskForm):
    block_start = TimeField('Start Time (block begins)', format='%H:%M', validators=[Optional()])
    block_end = TimeField('End Time (block ends)', format='%H:%M', validators=[Optional()])
    submit = SubmitField('Update Restriction')

class IPWhitelistForm(FlaskForm):
    whitelist = TextAreaField(
        'Allowed IPs (comma-separated)',
        description="Only these IPs can be used to log in.",
        validators=[Optional()]
    )
    submit = SubmitField('Update IP Whitelist')

    def validate_whitelist(self, field):
        raw_input = field.data or ""
        ip_list = [ip.strip() for ip in raw_input.split(",") if ip.strip()]
        for ip in ip_list:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValidationError(f"'{ip}' is not a valid IP address.")
