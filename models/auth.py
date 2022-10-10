from .db import BasicModel

class AuthModel(BasicModel):
    def __init__(self):
        super().__init__(model='auth_logs')
