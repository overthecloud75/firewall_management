from config import PAGE_DEFAULT

class Page:
    def __init__(self, page):
        self.page = page
        self.per_page = PAGE_DEFAULT['per_page']
        self.screen_pages = PAGE_DEFAULT['screen_pages']
        self.offset = (page - 1) * self.per_page

    def paginate(self, data_list, count=None):
        if count:
            pass
        else:
            if type(data_list) == list:
                count = len(data_list)
                data_list = data_list[self.offset:self.offset + self.per_page]
            else:
                count = data_list.count()
                data_list = data_list.limit(self.per_page).skip(self.offset)
        if count != 0:
            if count % self.per_page == 0:
                total_pages = int(count / self.per_page)
            else:
                total_pages = int(count / self.per_page) + 1
        else:
            total_pages = 1

        if self.page < 1:
            self.page = 1
        elif self.page > total_pages:
            self.page = total_pages

        start_page = (self.page - 1) // self.screen_pages * self.screen_pages + 1

        pages = []
        prev_num = start_page - self.screen_pages
        next_num = start_page + self.screen_pages

        if start_page - self.screen_pages > 0:
            has_prev = True
        else:
            has_prev = False
        if start_page + self.screen_pages > total_pages:
            has_next = False
        else:
            has_next = True
        if total_pages > self.screen_pages + start_page:
            for i in range(self.screen_pages):
                pages.append(i + start_page)
        elif total_pages < self.screen_pages:
            for i in range(total_pages):
                pages.append(i + start_page)
        else:
            for i in range(total_pages - start_page + 1):
                pages.append(i + start_page)

        paging = {'page': self.page,
                  'has_prev': has_prev,
                  'has_next': has_next,
                  'prev_num': prev_num,
                  'next_num': next_num,
                  'count': count,
                  'offset': self.offset,
                  'pages': pages,
                  'screen_pages': self.screen_pages,
                  'total_pages': total_pages
                  }
        return paging, data_list