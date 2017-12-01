from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators
from wtforms.validators import DataRequired

class RegisterForm(FlaskForm):
    username = StringField('Username',
        [validators.Length(min=4, max=25),
        validators.DataRequired()
    ])

    password = PasswordField('Password',
        [validators.EqualTo('confirm', message='Passwords must match'),
        validators.DataRequired()
    ])

    confirm = PasswordField('Confirm Password')

class LoginForm(FlaskForm):
   username = StringField('Username', [validators.DataRequired()])
   password = PasswordField('Password', [validators.DataRequired()])

class PasswordForm(FlaskForm):
   password = PasswordField('Password',
        [validators.EqualTo('confirm', message='Passwords must match'),
        validators.DataRequired()
    ])
   confirm = PasswordField('Confirm Password', [validators.DataRequired()])

class UpdateProfileForm(FlaskForm):
    name = StringField('Name')
    email = StringField('Email')
