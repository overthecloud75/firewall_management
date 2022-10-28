from flask import Blueprint, render_template, request, redirect, url_for

from models import Firewall, TicketModel, AccessModel
from forms import RuleUpdateForm, TicketUpdateForm
from configs import FIREWALL_COLUMN_HEADER, TICKET_COLUMN_HEADER, ACCESS_COLUMN_HEADER

# blueprint
bp = Blueprint('main', __name__, url_prefix='/manage')

@bp.route('/', methods=['GET', 'POST'])
def index():
    return redirect(url_for('main.firewall'))

@bp.route('/firewall', methods=['GET', 'POST'])
def firewall():
    page = request.args.get('page', default=1)

    management = Firewall()
    form = RuleUpdateForm()
    if request.method == 'POST' and form.validate_on_submit():
        request_data = {'ip': form.ip.data, 'ip_class':form.ip_class.data, 'protocol': form.protocol.data, 'port': form.port.data, 'block': form.block.data}
        management.post(request_data=request_data)

    column_header = FIREWALL_COLUMN_HEADER
    update_title = 'Firewall'

    paging, data_list = management.get(page=page)
    return render_template('pages/firewall.html', **locals())

@bp.route('/ticket', methods=['GET', 'POST'])
def ticket():
    page = request.args.get('page', default=1)

    management = TicketModel()
    form = TicketUpdateForm()
    if request.method == 'POST':
        request_data = {'_id': form.id.data, 'fix':form.fix.data}
        management.post(request_data=request_data)

    column_header = TICKET_COLUMN_HEADER
    update_title = 'Ticket'

    paging, data_list = management.get(page=page)
    return render_template('pages/ticket.html', **locals())

@bp.route('/ticket/<ticket>', methods=['GET', 'POST'])
def history(ticket):
    page = request.args.get('page', default=1)

    management = AccessModel()
    form = TicketUpdateForm()
    column_header = ACCESS_COLUMN_HEADER
    update_title = 'Access'

    paging, data_list = management.get_by_ticket(ticket, page=page)
    return render_template('pages/access.html', **locals())

@bp.route('/api/delete', methods=['POST'])
def delete_firewall_rule():
    form = RuleUpdateForm()
    if form.validate_on_submit():
        request_data = {'ip': form.ip.data, 'ip_class':form.ip_class.data, 'protocol': form.protocol.data, 'port': form.port.data, 'block': form.block.data}
        management = Firewall()
        management.delete(request_data=request_data)
        return 'validate', 200
    else:
        return 'not validate', 400


