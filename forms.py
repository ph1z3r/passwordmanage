from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional, NumberRange
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AddPasswordForm(FlaskForm):
    url = StringField('URL or Service Name', validators=[DataRequired(), Length(max=255)])
    username = StringField('Username or Email', validators=[DataRequired(), Length(max=128)])
    password = PasswordField('Password', validators=[DataRequired()])
    notes = TextAreaField('Notes', validators=[Optional()])
    
    # Password generation options
    generate_password = BooleanField('Generate Password', default=False)
    password_length = IntegerField('Password Length', validators=[Optional(), NumberRange(min=8, max=64)], default=16)
    include_uppercase = BooleanField('Include Uppercase Letters', default=True)
    include_digits = BooleanField('Include Digits', default=True)
    include_symbols = BooleanField('Include Special Characters', default=True)
    
    submit = SubmitField('Save Password')

class ViewPasswordForm(FlaskForm):
    submit = SubmitField('View Password')

class GeneratePasswordForm(FlaskForm):
    length = IntegerField('Password Length', validators=[NumberRange(min=8, max=64)], default=16)
    uppercase = BooleanField('Include Uppercase Letters', default=True)
    digits = BooleanField('Include Digits', default=True)
    symbols = BooleanField('Include Special Characters', default=True)
    submit = SubmitField('Generate Password')

class EditPasswordForm(FlaskForm):
    url = StringField('URL or Service Name', validators=[DataRequired(), Length(max=255)])
    username = StringField('Username or Email', validators=[DataRequired(), Length(max=128)])
    password = PasswordField('Password', validators=[DataRequired()])
    notes = TextAreaField('Notes', validators=[Optional()])
    
    # Password generation options
    generate_password = BooleanField('Generate Password', default=False)
    password_length = IntegerField('Password Length', validators=[Optional(), NumberRange(min=8, max=64)], default=16)
    include_uppercase = BooleanField('Include Uppercase Letters', default=True)
    include_digits = BooleanField('Include Digits', default=True)
    include_symbols = BooleanField('Include Special Characters', default=True)
    
    submit = SubmitField('Update Password')

class DeletePasswordForm(FlaskForm):
    confirm_delete = BooleanField('I confirm I want to delete this password', validators=[DataRequired()])
    submit = SubmitField('Delete Password')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')
