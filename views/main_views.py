from flask import Blueprint, render_template, request

from models import Firewall

# blueprint
bp = Blueprint('main', __name__, url_prefix='/firewall')

@bp.route('/')
def index():
    firewall = Firewall()
    paging, target_def, data_list = firewall.get(page=1)
    return render_template('firewall.html', **locals())