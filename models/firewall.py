from utils import Iptables, Page

iptables = Iptables()
iptables.enroll_chains()

class Firewall:
    def __init__(self):
        pass 

    def get(self, page=1):
        target_def, data_list = iptables.get_rules()
        get_page = Page(page)
        paging, data_list = get_page.paginate(data_list)
        return paging, target_def, data_list

    def post(self, request_data={}):
        ip = request_data['ip']
        protocol = request_data['protocol']
        port = request_data['port']
        block = request_data['block']
        iptables.post_rule(ip, protocol=protocol, port=port, block=block)
