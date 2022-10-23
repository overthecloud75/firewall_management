from utils import Iptables, Page

iptables = Iptables()

class Firewall:
    def __init__(self):
        pass 

    def get(self, page=1):
        data_list = iptables.get_rules()
        get_page = Page(page)
        paging, data_list = get_page.paginate(data_list)
        return paging, data_list

    def post(self, request_data={}):
        ip = request_data['ip']
        ip_class = request_data['ip_class']
        protocol = request_data['protocol']
        port = request_data['port']
        block = request_data['block']
        iptables.post_rule(ip, ip_class=ip_class, protocol=protocol, port=port, block=block)

    def delete(self, request_data={}):
        ip = request_data['ip']
        ip_class = request_data['ip_class']
        protocol = request_data['protocol']
        port = request_data['port']
        block = request_data['block']
        iptables.delete_rule(ip, ip_class=ip_class, protocol=protocol, port=port, block=block)
