from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import logging
import csv
import os 

from .mail import send_email 
from config import USE_NOTICE_EMAIL, CSV_FILE_NAME
try:
    from mainconfig import MONITORING_SITE, WEB_SITE, FIREWALL_SITE, MANUAL_SITE, ANALYZE_SITE
except:
    MONITORING_SITE = 'http://127.0.0.1:8000'
    WEB_SITE = {'domain': 'http://127.0.0.1:5000', 'ip': '127.0.0.1'}
    FIREWALL_SITE = 'http://127.0.0.1:5000/firewall'
    MANUAL_SITE = ''
    ANALYZE_SITE = 'https://www.abuseipdb.com/check/'

MONGO_URL = 'mongodb://localhost:27017/'

mongoClient = MongoClient(MONGO_URL)
db = mongoClient['report']

# createIndex https://velopert.com/560
db.fail2ban_logs.create_index([('timestamp', 1), ('ip', 1)])
db.auth_logs.create_index([('timestamp', 1), ('ip', 1)])
db.nginx_logs.create_index([('timestamp', 1), ('ip', 1)])

class BasicModel:
    def __init__(self, model):
        self.logger = logging.getLogger(__name__)
        self.model = model 
        self.collection = db[model]

        self.logger.info('{} start'.format(self.model))

    def _get_ticket_no(self, log):
        timestamp = log['timestamp']
        str_timestamp = timestamp.strftime('%y%m%d')
        s_timestamp = datetime(timestamp.year, timestamp.month, timestamp.day)
        f_timestamp = s_timestamp + timedelta(days=1)
        ticket_no = str(db['fail2ban_logs'].estimated_document_count({'timestamp' : {'$gte': s_timestamp, '$lt': f_timestamp}}))
        if len(ticket_no) == 1:
            ticket_no = 'TCK' + str_timestamp + '-000' + ticket_no
        elif len(ticket_no) == 2:
            ticket_no = 'TCK' + str_timestamp + '-00' + ticket_no
        elif len(ticket_no) == 3:
            ticket_no = 'TCK' + str_timestamp + '-0' + ticket_no
        else:
            ticket_no = 'TCK' + str_timestamp + '-' + ticket_no
        return ticket_no

    def _get_subject(self, log):
        ticket_no = self._get_ticket_no(log)
        subject_main = '[Auth 보안 관제: {}] '.format(ticket_no)     
       
        site = WEB_SITE['ip']
        attack_no = 0

        with open(CSV_FILE_NAME, 'w', encoding='utf-8', newline='') as csv_file:
            wr = csv.writer(csv_file)
            if 'origin' in log:
                if log['origin'] == '[modesecurity]':
                    subject_main = '[Web 보안 관제: : {}] '.format(ticket_no)
                    site = WEB_SITE['domain']
                    results = db['nginx_log'].find({'ip': log['ip']}).sort('timestamp', -1)
                    for result in results:
                        result_list = [result['timestamp'].strftime('%y-%m-%d %H:%M:%S'), result['ip'], result['method'], result['url'], result['http_version'], 
                                        result['status'], result['referer'], result['user_agent'], result['geo_ip']]
                        wr.writerow(result_list)
                        attack_no = attack_no + 1
                else:
                    results = db['auth_logs'].find({'ip': log['ip']}).sort('timestamp', -1)
                    for result in results:
                        result_list = [result['timestamp'].strftime('%y-%m-%d %H:%M:%S'), result['client'], result['ip'], result['id'], result['s_port'], result['geo_ip']]
                        wr.writerow(result_list)
                        attack_no = attack_no + 1

        subject = subject_main + '공격자 ip: ' + log['ip']
        if attack_no == 0 and os.path.isfile(CSV_FILE_NAME):
            os.remove(CSV_FILE_NAME)
        return subject, site, attack_no

    def _notice_email(self, log, signature=''):
        # check recipents  
        security_users = db['security_users'].find()
        email_list = []
        for user in security_users:
            email_list.append(user['email'])
        
        if USE_NOTICE_EMAIL:
            # https://techexpert.tips/ko/python-ko/파이썬-office-365를-사용하여-이메일-보내기
            # https://nowonbun.tistory.com/684 (참조자)

            subject, site, attack_no = self._get_subject(log)
            str_time = log['timestamp'].strftime('%y-%m-%d %H:%M:%S')

            body = '\n' \
                ' 안녕하세요. 보안 관제 센터입니다. {} 으로 다음의 공격이 확인되었습니다.\n' \
                '\n' \
                '- site         : {} \n' \
                '- time         : {} \n' \
                '- attacker ip  : {} \n' \
                '- attack num   : {} \n' \
                '- country      : {} \n' \
                '- signature    : {} \n' \
                '\n' \
                '다음의 site 에서 로그인 후 로그 분석이 가능합니다. \n' \
                '{} 파일이 있는 경우 {} 파일에서도 분석이 가능합니다. \n' \
                ' -> {} \n' \
                '\n' \
                '방화벽 차단이 필요한 경우 다음의 site 에 접속하셔서 실행해 주세요. \n' \
                ' -> {} \n' \
                '\n' \
                'Manual: {} \n' \
                '\n' \
                'Analyze the attack ip \n' \
                ' -> {} \n' \
                .format(site, site, str_time, log['ip'], attack_no, log['geo_ip'], signature, CSV_FILE_NAME, CSV_FILE_NAME, MONITORING_SITE, FIREWALL_SITE, MANUAL_SITE, ANALYZE_SITE + log['ip'])

            self.logger.info('email: {}'.format(subject))
            print('email: {}'.format(subject))
            sent = send_email(email_list=email_list, subject=subject, body=body, attached_file=CSV_FILE_NAME)
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
            self.logger.info('{}: {}'.format(self.model, log))
            print(self.model, log)
            
