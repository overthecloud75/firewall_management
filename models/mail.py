import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import COMMASPACE
from email.encoders import encode_base64
import os 

try:
    from mainconfig import ACCOUNT, MAIL_SERVER
except Exception as e:
    ACCOUNT = {
        'email': 'test@test.co.kr',
        'password': '*******',
    }
    MAIL_SERVER = {'host': 'smtp.office365.com', 'port': 587}
try:
    from mainconfig import CC
except Exception as e:
    # CC: cc email when notice email
    CC = None
    # CC = 'test@test.co.kr'

def send_email(email_list=[], subject=None, body=None, include_cc=False, attached_file=None):
    mimemsg = MIMEMultipart()
    mimemsg['From'] = ACCOUNT['email']
    mimemsg['To'] = COMMASPACE.join(email_list)
    if include_cc and CC is not None:
        mimemsg['Cc'] = CC
    mimemsg['Subject'] = subject
    mimemsg.attach(MIMEText(body))
    part = None 
    if attached_file and os.path.isfile(attached_file):
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(open(attached_file,'rb').read())
        encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename={}'.format(os.path.basename(attached_file)))
        mimemsg.attach(part)
        os.remove(attached_file)
    try:
        connection = smtplib.SMTP(host=MAIL_SERVER['host'], port=MAIL_SERVER['port'])
        connection.starttls()
        connection.login(ACCOUNT['email'], ACCOUNT['password'])
        connection.send_message(mimemsg)
        connection.quit()
        return True
    except Exception as e:
        print(e)
        return False
    