from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, PasswordField, DateField, SelectField, BooleanField
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, Optional, Length, EqualTo, Email

from configs import FIREWALL_STATUS

IP_CLASS_CHOICE = []
for choice in FIREWALL_STATUS['ip_class']:
    IP_CLASS_CHOICE.append((choice, choice))

PROTOCOL_CHOICE = []
for choice in FIREWALL_STATUS['protocol']:
    PROTOCOL_CHOICE.append((choice, choice))

PORT_CHOICE = []
for choice in FIREWALL_STATUS['port']:
    PORT_CHOICE.append((choice, choice))

BLOCK_CHOICE = []
for choice in FIREWALL_STATUS['block']:
    BLOCK_CHOICE.append((choice, choice))

class RuleUpdateForm(FlaskForm):
    ip = StringField('IP', validators=[DataRequired()])
    ip_class = SelectField('IP Class', choices=IP_CLASS_CHOICE)
    protocol = SelectField('Protocol', choices=PROTOCOL_CHOICE)
    port = SelectField('Port', choices=PORT_CHOICE)
    block = SelectField('Block', choices=BLOCK_CHOICE)

class TicketUpdateForm(FlaskForm):
    id = StringField('id', validators=[DataRequired()])
    timestamp = StringField('Occurance', validators=[DataRequired()])
    ticket = StringField('Ticket', validators=[DataRequired()])
    ip = StringField('Attacker IP', validators=[DataRequired()])
    geo_ip = StringField('Country', validators=[DataRequired()])
    attack_no = IntegerField('Attack No', validators=[DataRequired()])
    fix = TextAreaField('Action', validators=[DataRequired()])

    