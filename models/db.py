from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
from email.utils import COMMASPACE

from .mail import send_email 
from config import USE_NOTICE_EMAIL
try:
    from mainconfig import MONITORING_SITE, WEB_SITE, FIREWALL_SITE
except:
    MONITORING_SITE = 'http://127.0.0.1:8000'
    WEB_SITE = {'domain': 'http://127.0.0.1:5000', 'ip': '127.0.0.1'}
    FIREWALL_SITE = 'http://127.0.0.1:5000/firewall'

MONGO_URL = 'mongodb://localhost:27017/'

mongoClient = MongoClient(MONGO_URL)
db = mongoClient['report']

class BasicModel:
    def __init__(self, model):
        self.model = model 
        self.collection = db[model]

    def _notice_email(self, log, signature=''):
        # check recipents  
        security_users = db['security_users'].find()
        email_list = []
        for user in security_users:
            email_list.append(user['email'])
        email = COMMASPACE.join(email_list)

        if USE_NOTICE_EMAIL and email:
            # https://techexpert.tips/ko/python-ko/파이썬-office-365를-사용하여-이메일-보내기
            # https://nowonbun.tistory.com/684 (참조자)

            str_time = log['timestamp'].strftime("%y-%m-%d %H:%M:%S")
            subject_main = '[Auth 보안 관제] '         
            site = WEB_SITE['ip']
            if 'origin' in log:
                if log['origin'] == '[modesecurity]':
                    subject_main = '[Web 보안 관제] '
                    site = WEB_SITE['domain']
            
            subject = subject_main + '공격자 ip: ' + log['ip']

            body = '\n' \
                ' 안녕하세요. 보안 관제 센터입니다. {} 으로 다음의 공격이 확인되었습니다.\n' \
                '\n' \
                '- site      : {} \n' \
                '- 발생 시간  : {} \n' \
                '- 공격자 ip  : {} \n' \
                '- country   : {} \n' \
                '- signature : {} \n' \
                '\n' \
                '다음의 site 에서 로그인 후 로그 분석이 가능합니다. \n' \
                ' -> {} \n' \
                '\n' \
                '방화벽 차단이 필요한 경우 다음의 site 에 접속하셔서 실행해 주세요 \n' \
                ' -> {}' \
                .format(site, site, str_time, log['ip'], log['geo_ip'], signature, MONITORING_SITE, FIREWALL_SITE)

            sent = send_email(email=email, subject=subject, body=body)
            return sent 
        else:
            return False
    
    def _post(self, log):
        if self.model == 'fail2ban_logs':
            result = self.collection.find_one({'timestamp': log['timestamp'], 'ip': log['ip']})
            if not result:
                self.collection.update_one({'timestamp': log['timestamp'], 'ip': log['ip']}, {'$set': log}, upsert=True)
                self._notice_email(log)
        else:
            self.collection.update_one({'timestamp': log['timestamp'], 'ip': log['ip']}, {'$set': log}, upsert=True)

    def get_by_id(self, _id=''):
        try:
            data = self.collection.find_one({'_id': ObjectId(_id)})
        except Exception as e:
            data = None
            print(e)
        return data

    def many_post(self, log_list):
        log_list = reversed(log_list)
        for log in log_list:
            self._post(log)
            
