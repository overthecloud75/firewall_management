from .db import BasicModel

class NginxModel(BasicModel):
    def __init__(self):
        super().__init__(model='nginx_logs')


