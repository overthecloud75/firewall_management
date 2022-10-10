from datetime import datetime, timedelta
import re 
import csv
from flask import current_app

try:
    from config import FAIL2BAN_LOG_DIR, NGINX_ACCESS_LOG_DIR, AUTH_LOG_DIR, IPV4_FILE
except:
    FAIL2BAN_LOG_DIR = '/var/log/fail2ban.log'
    NGINX_ACCESS_LOG_DIR = '/var/log/nginx/access.log'
    AUTH_LOG_DIR = '/var/log/auth.log'
    
class Analyze:

    def __init__(self, interval=10, unit='m'):
        self.timestamp = datetime.now()
        if unit == 'm':
            self.interval = interval * 60
        else:
            self.interval = interval
        self.datetime_before_timestamp  = self.timestamp - timedelta(seconds=self.interval)

        self.obj = re.compile(r'(?P<ip>.*?)- - \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>.*?) (?P<bytes>.*?) "(?P<referer>.*?)" "(?P<ua>.*?)"')
        self.country_list = []
        self.s_ip_list = []
        self.f_ip_list = []

        with open(IPV4_FILE, 'r', encoding='cp949') as csvfile:
            rdr = csv.reader(csvfile)
            for i, line in enumerate(rdr):
                if i > 0:
                    self.country_list.append(line[1])
                    self.s_ip_list.append(line[2].split('.'))
                    self.f_ip_list.append(line[3].split('.'))

    def _parse_nginx_log(self, line):

        # https://pythonmana.com/2021/04/20210417005158969I.html
        result = self.obj.match(line)

        ip = result.group('ip')[:-1]
        timestamp = result.group('time')[:-6]
        datetime_timestamp = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S')

        request = result.group('request')
        request_list = request.split(' ')
        try:
            method = request_list[0]
            url = request_list[1]
            http_version = request_list[2]
        except:
            method = '-'
            url = request
            http_version = '-'
        status = int(result.group('status'))
        size = int(result.group('bytes'))
        referer = result.group('referer')
        user_agent = result.group('ua')

        geo_ip = self._find_country(ip)

        nginx_log_dict = {'timestamp': datetime_timestamp, 'ip': ip, 'method': method, 'url': url, 
                            'http_version': http_version, 'status': status, 'size': size, 'referer': referer, 'user_agent': user_agent, 'geo_ip': geo_ip}

        return nginx_log_dict

    def _parse_auth_log(self, line):
        new_line = line
        replace_word_list = ['Invalid user', 'invalid user', 'Disconnected from authenticating user', 'Failed password for', 'from', 
            'Connection closed by invalid user', 'Disconnected', 'port', 'Connection closed by authenticating user']
        for replace_word in replace_word_list:
            if replace_word in line:
                new_line = new_line.replace(replace_word, '')

        line_list = new_line.split(' ')
        new_line_list = []
        for value in line_list:
            if value == '':
                pass
            else:
                value = value.replace('\n', '')
                new_line_list.append(value)

        # https://www.adamsmith.haus/python/answers/how-to-convert-between-month-name-and-month-number-in-python
        month_name = new_line_list[0]   
        datetime_object = datetime.strptime(month_name, '%b')
        month_num = datetime_object.month
        hms = new_line_list[2].split(':')
        if month_num == self.timestamp.month:
            year = self.timestamp.year
        else:
            year = self.timestamp.year + 1
            
        datetime_timestamp = datetime(year, month_num, int(new_line_list[1]), int(hms[0]), int(hms[1]), int(hms[2]), 0)

        ip = new_line_list[6]
        geo_ip = self._find_country(ip)
        auth_log_dict = {'timestamp': datetime_timestamp, 'client': new_line_list[3], 'id': new_line_list[5], 'ip': ip, 's_port': int(new_line_list[7]), 'geo_ip': geo_ip}

        return auth_log_dict

    def _find_country(self, ip):
        ip_split = ip.split('.')
        ip_split0 = int(ip_split[0])
        ip_split1 = int(ip_split[1])
        ip_split2 = int(ip_split[2])
        ip_split3 = int(ip_split[3])

        geo_ip = 'un'
        for s_ip, f_ip, country in zip(self.s_ip_list, self.f_ip_list, self.country_list):
            if geo_ip != 'un':
                break
            for i in range(4):
                s_ip0 = int(s_ip[0])
                s_ip1 = int(s_ip[1])
                s_ip2 = int(s_ip[2])
                s_ip3 = int(s_ip[3])
                if ip_split0 < s_ip0:
                    break
                elif ip_split0 == s_ip0:
                    if ip_split1 < s_ip1:
                        break
                    elif ip_split1 == s_ip1:
                        if ip_split2 < s_ip2:
                            break
                        elif ip_split2 == s_ip2:
                            if ip_split3 < s_ip3:
                                break
                f_ip0 = int(f_ip[0])
                f_ip1 = int(f_ip[1])
                f_ip2 = int(f_ip[2])
                f_ip3 = int(f_ip[3])
                if ip_split0 > f_ip0:
                    break
                elif ip_split0 == f_ip0:
                    if ip_split1 > f_ip1:
                        break
                    elif ip_split1 == f_ip1:
                        if ip_split2 > f_ip2:
                            break
                        elif ip_split2 == f_ip2:
                            if ip_split3 > f_ip3:
                                break
                            else:
                                geo_ip = country
                        else:
                            geo_ip = country
                    else:
                        geo_ip = country
        return geo_ip
        
    def read_fail2ban_log(self):

        ban_list = []
        with open(FAIL2BAN_LOG_DIR, 'r', encoding='utf-8') as f:
            # https://nashorn.tistory.com/entry/Python-%ED%85%8D%EC%8A%A4%ED%8A%B8-%ED%8C%8C%EC%9D%BC-%EA%B1%B0%EA%BE%B8%EB%A1%9C-%EC%9D%BD%EA%B8%B0
            # python file 거꾸로 읽기 
            reverse_lines = f.readlines()[::-1]
            for i, line in enumerate(reverse_lines):

                line_list = line.split(' ')
                line_timestamp = line_list[0] + ' ' + line_list[1]
                datetime_timestamp = datetime.strptime(line_timestamp, '%Y-%m-%d %H:%M:%S,%f')

                if datetime_timestamp < self.datetime_before_timestamp:
                    break

                if 'Ban' in line_list:
                    ban_dict = {}
                    new_line_list = []
                    for i, value in enumerate(line_list):
                        if i > 1:
                            if value != '':
                                new_value = value.replace('\n', '')
                                new_line_list.append(new_value)
                    ip = new_line_list[-1]    
                    geo_ip = self._find_country(ip)

                    ban_dict = {'timestamp': datetime_timestamp, 'action': new_line_list[0], 'level': new_line_list[2], 'origin': new_line_list[3], 
                                'result': new_line_list[4], 'ip': ip, 'geo_ip': geo_ip}
                    ban_list.append(ban_dict)
        return ban_list

    def read_nginx_access_log(self):

        nginx_log_list = []
        with open(NGINX_ACCESS_LOG_DIR, 'r', encoding='utf-8') as f:

            reverse_lines = f.readlines()[::-1]
            for i, line in enumerate(reverse_lines):
                try:
                    nginx_log_dict = self._parse_nginx_log(line)
                    if nginx_log_dict['timestamp'] < self.datetime_before_timestamp:
                        break
                
                    if nginx_log_dict['status'] in [400, 403, 404]:
                        nginx_log_list.append(nginx_log_dict)
                except Exception as e:
                    # current_app.logger.info('nginx log error: {}, line: {}'.format(e, line))
                    print(e, line)
        return nginx_log_list

    def read_auth_log(self):

        auth_log_list = []
        with open(AUTH_LOG_DIR, 'r', encoding='utf-8') as f:
            reverse_lines = f.readlines()[::-1]
            for i, line in enumerate(reverse_lines):
                if 'pam_unix(sshd:auth)' in line:
                    pass
                elif 'Received disconnect' in line:
                    pass
                elif 'CRON' in line:
                    pass
                elif 'error' in line:
                    pass
                elif 'Accepted password for' in line:
                    pass
                else:
                    if 'ssh2' in line:
                        auth_log_dict = self._parse_auth_log(line)
                        if auth_log_dict['timestamp'] < self.datetime_before_timestamp:
                            break
                        auth_log_list.append(auth_log_dict)

        return auth_log_list

if __name__ == '__main__':
    analyze = Analyze()
    # nginx_log_list = analyze.read_nginx_access_log()
    auth_log_list = analyze.read_auth_log()

