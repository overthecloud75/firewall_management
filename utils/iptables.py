import iptc
import os
import ipaddress 

from config import FW_CHAINS

'''
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-N RH-Firewall-1-INPUT
-N f2b-modesecurity
-N f2b-sshd
-A INPUT -p tcp -m multiport --dports 80,443 -j f2b-modesecurity
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A f2b-modesecurity -j RETURN
-A f2b-sshd -s 184.82.198.131/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -s 68.183.83.242/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -j RETURN
'''

class Iptables:
    def __init__(self):
        pass

    # https://codefather.tech/blog/validate-ip-address-python/
    def _validate_ip_address(self, address):
        result = True
        try:
            ip = ipaddress.ip_address(address)
            print('IP address {} is valid. The object returned is {}'.format(address, ip))
        except ValueError:
            print('IP address {} is not valid'.format(address)) 
            result=False
        return result

    # https://gist.github.com/zhangchunlin/1513742/89a38864b41e002e4a6600a946c076ad0fe6f7bb
    def _do_cmd(self, cmd):
        os.system(cmd)

    def _enrole_chain(self, chain):
        cmd = 'iptables -N {chain}'.format(chain=chain)
        self._do_cmd(cmd)

    def _target_role(self, port, chain, protocol='tcp'):
        dports = '80,443'
        if port == 'ssh': 
            dports = '22'
        cmd = 'iptables -A INPUT -p {protocol} -m multiport --dports {dports} -j {chain}'.format(protocol=protocol, dports=dports, chain=chain)
        self._do_cmd(cmd)

    def enroll_chains(self):
        chains = iptc.easy.get_chains('filter')
        for port, chain in FW_CHAINS.items():
            if not chain in chains:
                self._enrole_chain(chain)
                self._target_role(port, chain)

    def post_rule(self, ip, ip_class='/32', protocol='tcp', port='all', block='DROP'):
        chain = FW_CHAINS[port]
        if self._validate_ip_address(ip):
            if block=='ACCEPT':
                cmd = 'iptables -A {chain} -s {ip_type} -j {block}'.format(ip_type=ip + ip_class, block=block, chain=chain)
            elif block=='REJECT':
                cmd = 'iptables -A {chain} -s {ip_type} -j {block} --reject-with icmp-port-unreachable'.format(ip_type=ip + ip_class, block=block, chain=chain)
            else:
                cmd = 'iptables -A {chain} -s {ip_type} -j {block}'.format(ip_type=ip + ip_class, block='DROP', chain=chain)
            self._do_cmd(cmd)

    def delete_rule(self, ip, ip_class='/32', protocol='tcp', port='all', block='DROP'):
        chain = FW_CHAINS[port]
        if self._validate_ip_address(ip):
            if block=='ACCEPT':
                cmd = 'iptables -D {chain} -s {ip_type} -j {block}'.format(ip_type=ip + ip_class, block=block, chain=chain)
            elif block=='REJECT':
                cmd = 'iptables -D {chain} -s {ip_type} -j {block} --reject-with icmp-port-unreachable'.format(ip_type=ip + ip_class, block=block, chain=chain)
            else:
                cmd = 'iptables -D {chain} -s {ip_type} -j {block}'.format(ip_type=ip + ip_class, block='DROP', chain=chain)
            self._do_cmd(cmd)

    def get_rules(self):
        target_def = {}
        iptables = {}
        filter_list = []

        chains = iptc.easy.get_chains('filter')
        for chain in chains:
            filters = iptc.easy.dump_chain('filter', chain)
            if chain == 'INPUT':
                for filter in filters:
                    target_def[filter['target']] = filter
            elif chain in target_def:
                for filter in filters:
                    if 'src' in filter: 
                        filter['name'] = chain
                        filter['message'] = ''
                        filter['ip'] = filter['src'].split('/')[0]
                        filter['ip_class'] = '/' + filter['src'].split('/')[1]
                        del filter['counters']
                        if 'REJECT' in filter['target']:
                            filter['block'] = 'REJECT'
                            filter['message'] = filter['target']['REJECT']['reject-with']
                        elif 'ACCEPT' in filter['target']:
                            filter['block'] = 'ACCEPT'
                        elif 'DROP' in filter['target']:
                            filter['block'] = 'DROP'
                        filter_list.append(filter)
        return target_def, filter_list


