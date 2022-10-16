import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import COMMASPACE
from email.encoders import encode_base64
import os 

from configs import ACCOUNT, MAIL_SERVER, CC

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
    