import logging
from utils import Page
from datetime import datetime 

from .db import BasicModel

class AccessModel(BasicModel):

    def __init__(self, model='nginx_access_logs', need_notice=False):
        self.logger = logging.getLogger(__name__)
        super().__init__(model=model)

        self.logger.info('{} start'.format(self.model))

    def get_by_ticket(self, ticket, page=1):
        result = self.db['tickets'].find_one({'ticket': ticket})
        if result:
            data_list = self._get_by_ip(result['ip'])
        else:
            data_list = []
        get_page = Page(page)
        paging, data_list = get_page.paginate(data_list, collection=self.collection)
        return paging, data_list
