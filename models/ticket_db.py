import logging
from utils import Page

from .db import BasicModel

class TicketModel(BasicModel):

    def __init__(self, model='tickets', need_notice=False):
        self.logger = logging.getLogger(__name__)
        super().__init__(model=model)

        self.logger.info('{} start'.format(self.model))

    def get(self, page=1):
        data_list = self.collection.find()
        get_page = Page(page)
        paging, data_list = get_page.paginate(data_list, collection=self.collection)
        return paging, data_list


   