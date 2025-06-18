from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, FileField, HiddenField
from wtforms.validators import DataRequired, Email, Length, Optional, URL


class MessageForm(FlaskForm):
    """Form for adding/editing messages."""

    text = TextAreaField('Message', validators=[DataRequired()])
    parent_id = HiddenField('Parent ID')  # New hidden field for replies


class UserAddForm(FlaskForm):
    """Form for adding users."""

    username = StringField('Username', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6)])
    image_url = StringField('(Optional) Image URL')


class UserEditForm(FlaskForm):
    username = StringField("Username")
    email = StringField("Email")
    image_url = FileField("Profile Image", validators=[Optional()])
    header_image_url = FileField("Header Image", validators=[Optional()])
    bio = TextAreaField("Bio")
    location = StringField("Location")
    twitter_url = StringField("Twitter URL", validators=[Optional(), URL(require_tld=True, message="Invalid URL")])
    facebook_url = StringField("Facebook URL", validators=[Optional(), URL(require_tld=True, message="Invalid URL")])
    linkedin_url = StringField("LinkedIn URL", validators=[Optional(), URL(require_tld=True, message="Invalid URL")])
    password = PasswordField("New Password", validators=[Optional(), Length(min=6)])

class LoginForm(FlaskForm):
    """Login form."""

    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6)])

class ResendConfirmationForm(FlaskForm):
    """Form for resending confirmation email"""

    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Resend Confirmation Email')

class PasswordResetRequestForm(FlaskForm):
    """Form for requesting a password reset."""
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class PasswordResetForm(FlaskForm):
    """Form for resetting the password."""
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Reset Password')
