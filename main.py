import os
from logging.config import dictConfig

from flask import Flask
from config import BASE_DIR, LOG_DIR

if os.path.exists(os.path.join(BASE_DIR, LOG_DIR)):
    pass
else:
    os.mkdir(os.path.join(BASE_DIR, LOG_DIR))


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
    app.run(host='127.0.0.1', debug=True)