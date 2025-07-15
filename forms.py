from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_wtf.recaptcha import RecaptchaField
from wtforms import ValidationError
from flask_login import current_user

# ✅ Existing Forms

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

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

# ✅ Original RegisterForm (used in old /register route, now deprecated)
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=25, message="Username must be 3-25 characters.")
    ])
    email = StringField('Email', validators=[
        DataRequired(), Email(message="Enter a valid email.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='At least 8 characters.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')

    # Duplicate checks
    def validate_email(self, field):
        from models import User
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email is already registered.')

    def validate_username(self, field):
        from models import User
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username is already taken.')

# ✅ New Forms for Two-Step Registration

class EmailForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Next')

class RegisterDetailsForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=25, message="Username must be 3-25 characters.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='At least 8 characters.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')

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
    submit = SubmitField('Delete Account')

class VerifyTOTPForm(FlaskForm):
    token = StringField('Authentication Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')
