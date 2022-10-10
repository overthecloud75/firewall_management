from .db import BasicModel

class Fail2BanModel(BasicModel):
    def __init__(self):
        super().__init__(model='fail2ban_logs')
