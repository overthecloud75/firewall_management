import iptc
import os 

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

def get_iptables():
    
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
                    if 'REJECT' in filter['target']:
                        filter['block'] = 'deny'
                        filter['message'] = filter['target']['REJECT']['reject-with']
                    filter_list.append(filter)
    return target_def, filter_list
