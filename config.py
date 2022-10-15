import os

# log
BASE_DIR= os.getcwd()
LOG_DIR = 'logs'

if os.path.exists(os.path.join(BASE_DIR, LOG_DIR)):
    pass
else:
    os.mkdir(os.path.join(BASE_DIR, LOG_DIR))

# evidence
EVIDENCE_DIR = 'evidence'
if os.path.exists(os.path.join(BASE_DIR, EVIDENCE_DIR)):
    pass
else:
    os.mkdir(os.path.join(BASE_DIR, EVIDENCE_DIR))

# csv_file_name 
CSV_FILE_NAME = 'evidence.csv'

# paging
PAGE_DEFAULT = {
    'per_page': 20,
    'screen_pages': 10
}

# firewall_status 
FIREWALL_STATUS = {
    'ip_class': ['/32', '/24'],
    'protocol': ['tcp', 'udp', 'all'],
    'port': ['ssh', 'web', 'all'],
    'block': ['DROP', 'REJECT', 'ACCEPT']
}

# chains 
FW_CHAINS = {
    'ssh': 'FW-ssh', 
    'web': 'FW-web',
    'all': 'FW-all',
}

# Fail2Ban, Nginx, Auth log 
FAIL2BAN_LOG_DIR = '/var/log/fail2ban.log'
NGINX_ACCESS_LOG_DIR = '/var/log/nginx/access.log'
NGINX_ERROR_LOG_DIR = '/var/log/nginx/error.log'
AUTH_LOG_DIR = '/var/log/auth.log'
IPV4_FILE = 'ipv4.csv'

# email Setting
USE_NOTICE_EMAIL = True


# log_keys
NGINX_ACCESS_LOG_KEYS = ['timestamp', 'ip', 'method', 'url', 'http_version', 'status', 'size', 'referer', 'user_agent', 'geo_ip']
AUTH_LOG_KEYS = ['timestamp', 'client', 'ip', 'id', 's_port', 'geo_ip']

AUTH_LOG_FILTERING = ['Invalid user', 'invalid user', 'Disconnected from authenticating user', 'Failed password for', 'from', 
            'Connection closed by invalid user', 'Disconnected', 'port', 'Connection closed by authenticating user', 'Failed none for']
