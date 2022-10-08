from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, DateField, SelectField, BooleanField
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, Optional, Length, EqualTo, Email

class RuleUpdateForm(FlaskForm):
    ip = StringField('ip', validators=[DataRequired()])
    ip_class = StringField('ip_class', validators=[DataRequired()])
    protocol = StringField('protocol', validators=[DataRequired()])
    port = StringField('port', validators=[DataRequired()])
    block = StringField('block', validators=[DataRequired()])
    