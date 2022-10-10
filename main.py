import os
import threading
import time
from logging.config import dictConfig
from flask import Flask

from models import NginxModel, AuthModel, Fail2BanModel
from utils import Analyze
from config import BASE_DIR, LOG_DIR

def read_log():

    nginx_model = NginxModel()
    auth_model = AuthModel()
    fail2ban_model = Fail2BanModel()
        
    while True:
        # timestamp를 refresh
        analyze = Analyze()  
        ban_list = analyze.read_fail2ban_log()
        nginx_log_list = analyze.read_nginx_access_log()
        auth_log_list = analyze.read_auth_log()
        print(analyze.timestamp)
        nginx_model.many_post(nginx_log_list)
        auth_model.many_post(auth_log_list)
        fail2ban_model.many_post(ban_list)
        time.sleep(300)
        
def create_app():
    # https://flask.palletsprojects.com/en/2.0.x/logging/
    # https://wikidocs.net/81081
    dictConfig({
        'version': 1,
        'formatters': {
            'default': {
                'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
            }
        },
        'handlers': {
            'file': {
                'level': 'INFO',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(BASE_DIR, LOG_DIR, 'project.log'),
                'maxBytes': 1024 * 1024 * 5,  # 5 MB
                'backupCount': 5,
                'formatter': 'default',
            },
        },
        'root': {
            'level': 'INFO',
            'handlers': ['file']
        }
    })

    app = Flask(__name__)
    # https://wikidocs.net/81066

    app.config['SECRET_KEY'] = os.urandom(32)
    app.config['SESSION_COOKIE_SECURE'] = True

    from views import main_views
    app.register_blueprint(main_views.bp)

    return app

if __name__ == '__main__':
    app = create_app()
    
    th = threading.Thread(target=read_log)
    th.daemon = True
    th.start()

    app.run(host='127.0.0.1', debug=False, threaded=True)