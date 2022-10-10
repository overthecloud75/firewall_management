from .iptables import Iptables
from .page import Page
from .analyze import Analyze

def log_message(headers):
    referer = ''
    remote_addr = ''
    url = ''
    if 'Referer' in headers:
        referer = headers['Referer']
    if 'X-Forwarded-For' in headers:
        remote_addr = headers['X-Forwarded-For']
    if 'X-Original-Url' in headers:
        url = headers['X-Original-Url']
    user_agent = headers['User-Agent']
    message = remote_addr + ' - ' + referer + ' - ' + url + ' - ' + user_agent
    return message