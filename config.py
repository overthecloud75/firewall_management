import os

# log
BASE_DIR= os.getcwd()
LOG_DIR = 'logs'

if os.path.exists(os.path.join(BASE_DIR, LOG_DIR)):
    pass
else:
    os.mkdir(os.path.join(BASE_DIR, LOG_DIR))

# paging
PAGE_DEFAULT = {
    'per_page': 20,
    'screen_pages': 10
}

# firewall_status 
FIREWALL_STATUS = {
    'protocol': ['tcp', 'udp', 'all'],
    'port': ['ssh', 'web', 'all'],
    'block': ['deny', 'allow']
}