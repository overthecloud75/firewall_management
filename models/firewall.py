from utils import get_iptables, Page


class Firewall:
    def __init__(self):
        pass 

    def get(self, page=1):
        target_def, data_list = get_iptables()
        get_page = Page(page)
        paging, data_list = get_page.paginate(data_list)
        return paging, target_def, data_list

    def post(self, request_data={}):
        print(request_data)
