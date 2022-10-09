from flask import Blueprint, render_template, request

from models import Firewall
from form import RuleUpdateForm
from config import FIREWALL_STATUS

firewall = Firewall()

# blueprint
bp = Blueprint('main', __name__, url_prefix='/firewall')

@bp.route('/', methods=['GET', 'POST'])
def index():
    page = request.args.get('page', default=1)
    data = {}
    firewall_status = FIREWALL_STATUS
    form = RuleUpdateForm()
    if request.method == 'POST' and form.validate_on_submit():
        request_data = {'ip': form.ip.data, 'ip_class':form.ip_class.data, 'protocol': form.protocol.data, 'port': form.port.data, 'block': form.block.data}
        firewall.post(request_data=request_data)
        data = request_data

    paging, target_def, data_list = firewall.get(page=page)
    return render_template('firewall/firewall.html', **locals())

@bp.route('/api/delete', methods=['POST'])
def api():
    form = RuleUpdateForm()
    if form.validate_on_submit():
        request_data = {'ip': form.ip.data, 'ip_class':form.ip_class.data, 'protocol': form.protocol.data, 'port': form.port.data, 'block': form.block.data}
        firewall.delete(request_data=request_data)
        return 'validate', 200
    else:
        return 'not validate', 400


