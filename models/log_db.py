from datetime import datetime, timedelta
import logging
import csv
import os 

from .db import BasicModel
from .mail import send_email 
from configs import BASE_DIR, EVIDENCE_DIR, CSV_FILE_NAME, USE_NOTICE_EMAIL, NGINX_ACCESS_LOG_KEYS, AUTH_LOG_KEYS
from configs import MONITORING_SITE, WEB_SITE, FIREWALL_SITE, MANUAL_SITE, ANALYZE_SITE

class LogModel(BasicModel):
    def __init__(self, model='fail2ban_logs', need_notice=False):
        self.logger = logging.getLogger(__name__)
        super().__init__(model=model)

        self.logger.info('{} start'.format(self.model))
        self.need_notice = need_notice

    def _get_ticket(self, log):
        timestamp = log['timestamp']
        str_timestamp = timestamp.strftime('%y%m%d')
        s_timestamp = datetime(timestamp.year, timestamp.month, timestamp.day)
        f_timestamp = s_timestamp + timedelta(days=1)
        ticket_no = 0
        results = self.db['fail2ban_logs'].find({'timestamp' : {'$gte': s_timestamp, '$lt': f_timestamp}})
        for result in results:
            ticket_no = ticket_no + 1
        ticket_no = str(ticket_no)
        if len(ticket_no) == 1:
            ticket_no = 'TCK' + str_timestamp + '-000' + ticket_no
        elif len(ticket_no) == 2:
            ticket_no = 'TCK' + str_timestamp + '-00' + ticket_no
        elif len(ticket_no) == 3:
            ticket_no = 'TCK' + str_timestamp + '-0' + ticket_no
        else:
            ticket_no = 'TCK' + str_timestamp + '-' + ticket_no
        return ticket_no

    def _write_csv_and_get_attack_no(self, results, wr, keys, attack_no):
        wr.writerow(keys)
        for result in results:
            result_list = []
            for key in keys:
                if key == 'timestamp':
                    result_list.append(result[key].strftime('%y-%m-%d %H:%M:%S'))
                else:
                    result_list.append(result[key])
            wr.writerow(result_list)
            attack_no = attack_no + 1
        return attack_no

    def _post_ticket(self, log, ticket_no, attack_no):
        ticket_info = log
        ticket_info['model'] = self.model
        ticket_info['ticket'] = ticket_no
        ticket_info['attack_no'] = attack_no
        self.db['tickets'].insert_one(ticket_info)

    def _get_subject(self, log):
        '''
            1. get ticket_no 
            2. make evidence file
            3. get attack_no 
            4. save ticket info 
        '''
        ticket_no = self._get_ticket(log)
           
        subject_main = '[보안 관제]'
        site = WEB_SITE['ip']
        attack_no = 0

        csv_file_name = os.path.join(BASE_DIR, EVIDENCE_DIR, ticket_no + '_' + CSV_FILE_NAME)

        with open(csv_file_name, 'w', encoding='utf-8', newline='') as csv_file:
            wr = csv.writer(csv_file)
            if 'origin' in log:
                if log['origin'] == '[modesecurity]':
                    subject_main = '[{} : {} 보안 관제] '.format(ticket_no, 'WEB')
                    site = WEB_SITE['domain']
                    results = self.db['nginx_access_logs'].find({'ip': log['ip']}).sort('timestamp', -1)
                    attack_no = self._write_csv_and_get_attack_no(results, wr, NGINX_ACCESS_LOG_KEYS, attack_no)
                else:
                    subject_main = '[{} : {} 보안 관제] '.format(ticket_no, 'AUTH')  
                    results = self.db['auth_logs'].find({'ip': log['ip']}).sort('timestamp', -1)
                    attack_no = self._write_csv_and_get_attack_no(results, wr, AUTH_LOG_KEYS, attack_no)

        subject = subject_main + '공격자 ip: ' + log['ip']

        self._post_ticket(log, ticket_no, attack_no)
        return subject, site, attack_no, csv_file_name

    def _notice_email(self, log, signature=''):
        # check recipents  
        security_users = self.db['security_users'].find()
        email_list = []
        for user in security_users:
            email_list.append(user['email'])
        
        if USE_NOTICE_EMAIL:
            # https://techexpert.tips/ko/python-ko/파이썬-office-365를-사용하여-이메일-보내기
            # https://nowonbun.tistory.com/684 (참조자)

            subject, site, attack_no, csv_file_name = self._get_subject(log)
            str_time = log['timestamp'].strftime('%y-%m-%d %H:%M:%S')

            body = '\n' \
                ' 안녕하세요. 보안 관제 센터입니다. {} 으로 다음의 공격이 확인되었습니다.\n' \
                '\n' \
                '- site         : {} \n' \
                '- time         : {} \n' \
                '- attacker ip  : {} \n' \
                '- attack num   : {} \n' \
                '- country      : {} \n' \
                '\n' \
                '다음의 site 에서 로그인 후 로그 분석이 가능합니다. \n' \
                '{} 파일이 있는 경우 그 파일에서도 분석이 가능합니다. \n' \
                ' -> {} \n' \
                '\n' \
                '방화벽 차단이 필요한 경우 다음의 site 에 접속하셔서 실행해 주세요. \n' \
                ' -> {} \n' \
                '\n' \
                'Manual: {} \n' \
                '\n' \
                'Analyze the attacker ip \n' \
                ' -> {} \n' \
                .format(site, site, str_time, log['ip'], attack_no, log['geo_ip'], CSV_FILE_NAME, MONITORING_SITE, FIREWALL_SITE, MANUAL_SITE, ANALYZE_SITE + log['ip'])

            self.logger.info('email: {}'.format(subject))
            print('email: {}'.format(subject))
            sent = send_email(email_list=email_list, subject=subject, body=body, attached_file=csv_file_name)
            return sent 
        else:
            return False
    
    def _post(self, log):
        if 'ip' in log:
            if self.need_notice:
                if 'url' in log:
                    result = self.collection.find_one({'timestamp': log['timestamp'], 'ip': log['ip'], 'url': log['url']})
                    if not result:
                        self.collection.update_one({'timestamp': log['timestamp'], 'ip': log['ip'], 'url': log['url']}, {'$set': log}, upsert=True)
                        self._notice_email(log)
                else:
                    result = self.collection.find_one({'timestamp': log['timestamp'], 'ip': log['ip']})
                    if not result:
                        self.collection.update_one({'timestamp': log['timestamp'], 'ip': log['ip']}, {'$set': log}, upsert=True)
                        self._notice_email(log)
            else:
                self.collection.update_one({'timestamp': log['timestamp'], 'ip': log['ip']}, {'$set': log}, upsert=True)

    def many_post(self, log_list):
        log_list = reversed(log_list)
        for log in log_list:
            self.logger.info('{}: {}'.format(self.model, log))
            self._post(log)

