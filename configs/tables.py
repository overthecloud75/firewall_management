# title_list

FIREWALL_COLUMN_HEADER = [
    {
        'accessor': 'name',
        'header': 'Name',
    },
    {
        'accessor': 'ip',
        'header': 'ip',
    },
    {
        'accessor': 'ip_class',
        'header': 'Class',
    },
    {
        'accessor': 'protocol',
        'header': 'Protocol',
    },
    {
        'accessor': 'port',
        'header': 'Port',
    },
    {
        'accessor': 'block',
        'header': 'BLOCK',
    },
    {
        'accessor': 'message',
        'header': 'Message',
    },
]

# title_list

TICKET_COLUMN_HEADER = [
    {
        'accessor': 'timestamp',
        'header': 'Occurance',
    },
    {
        'accessor': 'ticket',
        'header': 'Ticket',
    },
    {
        'accessor': 'ip',
        'header': 'Attacker IP',
    },
    {
        'accessor': 'geo_ip',
        'header': 'Country',
    },
    {
        'accessor': 'attack_no',
        'header': 'Attack NO',
    },
    {
        'accessor': 'origin',
        'header': 'Origin'
    },
    {
        'accessor': 'fix',
        'header': 'Action'
    },
    {
        'accessor': 'fix_timestamp',
        'header': 'Action Time'
    }
]

# title_list
'''
    ip: '207.46.13.54',
    timestamp: ISODate("2022-10-10T10:33:06.000Z"),
    geo_ip: 'US',
    http_version: 'HTTP/1.1',
    method: 'GET',
    referer: '-',
    size: 186,
    status: 403,
    url: '/firewall',
    user_agent: 'Mozilla/5.0
'''

ACCESS_COLUMN_HEADER = [
    {
        'accessor': 'timestamp',
        'header': 'Occurance',
    },
    {
        'accessor': 'ip',
        'header': 'Attacker IP',
    },
    {
        'accessor': 'geo_ip',
        'header': 'Country',
    },
    {
        'accessor': 'status',
        'header': 'Status',
    },
    {
        'accessor': 'http_version',
        'header': 'HTTP Version',
    },
    {
        'accessor': 'method',
        'header': 'Method'
    },
    {
        'accessor': 'url',
        'header': 'Url'
    },
    {
        'accessor': 'user_agent',
        'header': 'User Agent'
    }
]