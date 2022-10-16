from flask import Blueprint, render_template, request, redirect, url_for

from models import Firewall, TicketModel
from form import RuleUpdateForm
from configs import FIREWALL_STATUS, FIREWALL_COLUMN_HEADER

# blueprint
bp = Blueprint('main', __name__, url_prefix='/manage')

@bp.route('/', methods=['GET', 'POST'])
def index():
    return redirect(url_for('main.firewall'))

@bp.route('/firewall', methods=['GET', 'POST'])
def firewall():
    page = request.args.get('page', default=1)
    data = {}

    management = Firewall()
    form = RuleUpdateForm()
    if request.method == 'POST' and form.validate_on_submit():
        request_data = {'ip': form.ip.data, 'ip_class':form.ip_class.data, 'protocol': form.protocol.data, 'port': form.port.data, 'block': form.block.data}
        management.post(request_data=request_data)
        data = request_data

    firewall_status = FIREWALL_STATUS
    column_header = FIREWALL_COLUMN_HEADER
    button_title = 'Firewall Update'
    no_info = 'firewall 정보가 없습니다.'

    paging, data_list = management.get(page=page)
    return render_template('pages/firewall.html', **locals())

@bp.route('/ticket', methods=['GET'])
def ticket():
    page = request.args.get('page', default=1)
    data = {}

    management = TicketModel()
    form = RuleUpdateForm()

    firewall_status = FIREWALL_STATUS
    column_header = FIREWALL_COLUMN_HEADER
    button_title = 'Ticket Update'
    no_info = 'ticket 정보가 없습니다.'

    paging, data_list = management.get(page=page)
    return render_template('pages/ticket.html', **locals())

@bp.route('/api/delete', methods=['POST'])
def api():
    form = RuleUpdateForm()
    if form.validate_on_submit():
        request_data = {'ip': form.ip.data, 'ip_class':form.ip_class.data, 'protocol': form.protocol.data, 'port': form.port.data, 'block': form.block.data}
        firewall_management.delete(request_data=request_data)
        return 'validate', 200
    else:
        return 'not validate', 400


