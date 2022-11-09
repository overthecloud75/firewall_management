import os
import threading
import time
from logging.config import dictConfig
from flask import Flask
from datetime import datetime

from models import LogModel
from utils import Analyze
from configs import BASE_DIR, LOG_DIR

def read_log():

    nginx_access_model = LogModel(model='nginx_access_logs')
    nginx_error_model = LogModel(model='nginx_error_logs')
    auth_model = LogModel(model='auth_logs')
    fail2ban_model = LogModel(model='fail2ban_logs', need_notice=True)
    analyze = Analyze()  
    while True:
        # timestamp를 refresh
        analyze.timestamp = datetime.now()
        print(analyze.timestamp)
        ban_list = analyze.read_fail2ban_log()
        nginx_access_log_list = analyze.read_nginx_access_log()
        nginx_error_log_list = analyze.read_nginx_error_log()
        auth_log_list = analyze.read_auth_log()

        nginx_access_model.many_post(nginx_access_log_list)
        nginx_error_model.many_post(nginx_error_log_list)
        auth_model.many_post(auth_log_list)
        fail2ban_model.many_post(ban_list)

        analyze.previous_timestamp = analyze.timestamp

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
    ### jinja update 
    app.jinja_env.globals.update(
        enumerate=enumerate, 
    )

    from views import main_views
    app.register_blueprint(main_views.bp)

    return app

if __name__ == '__main__':
    app = create_app()
    
    th = threading.Thread(target=read_log)
    th.daemon = True
    th.start()

    app.run(host='127.0.0.1', debug=False, threaded=True)