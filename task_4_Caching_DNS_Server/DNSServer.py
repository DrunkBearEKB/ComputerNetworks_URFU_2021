from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from collections import namedtuple


IP_HOST = '192.168.88.152'
IP_DNS = '192.168.88.1'
HANDLED_RECORD_TYPES = [1, 28, 2, 12, 5]  # [A, AAAA, NS, PTR, CNAME]


class DNSServer:
    def __init__(self, flag_debug=False, flag_intercept_mode=False):
        self.__data_base = dict()
        self.__dict_waiting_response = dict()

        self.__flag_debug = flag_debug
        self.__flag_intercept_mode = flag_intercept_mode

    def start(self):
        self.__load_data_base()

        self.__log('info', f'Server started at [{datetime.now()}]')

        while True:
            sniff(filter='udp port 53', store=0,
                  prn=lambda package: self.__handle_package(package))

    def __load_data_base(self):
        self.__data_base = dict()

        with open('database.txt', mode='r') as file_database:
            for line in file_database.readlines():
                line_parsed = line.split('\t')

                _record = eval(line_parsed[2])
                _record = record(_record.data,
                                 int(_record.authority),
                                 int(_record.ttl),
                                 float(_record.time))

                if _record.time > time.time():
                    if line_parsed[0] not in self.__data_base.keys():
                        self.__data_base[line_parsed[0]] = dict()
                    self.__data_base[line_parsed[0]][line_parsed[1]] = _record

        self.__save_data_base()
        self.__log('info', 'Database loaded successfully!')

    def __save_data_base(self):
        with open('database.txt', mode='w') as file_database:
            for key, value in self.__data_base.items():
                for _key, _record in value.items():
                    if _record.time > time.time():
                        file_database.write(f'{key}\t{_key}\t{_record}\n')

    def __handle_package(self, package):
        if IP in package and package.haslayer(DNS):
            ip_src, ip_dst = DNSServer.__get_ip(package)

            if package.getlayer(DNS).qr == 0:
                if str(ip_dst) == IP_DNS:
                    return
                if str(ip_dst) == IP_HOST:
                    prefixes = ['request']
                elif self.__flag_intercept_mode:
                    prefixes = ['request', 'intercept']
                else:
                    return
                suffixes = [f'data={package.getlayer(DNSQR).qname.decode()}',
                            f'type={package.getlayer(DNSQR).qtype}']
                self.__handle_request(package)

            else:
                if str(ip_dst) == IP_HOST:
                    prefixes = ['response']
                elif self.__flag_intercept_mode:
                    prefixes = ['response', 'intercept']
                else:
                    return
                suffixes = None

                self.__handle_response(package)

            self.__log(
                'info', f'{ip_src} -> {ip_dst}',
                prefixes=prefixes,
                suffixes=suffixes)

    def __handle_request(self, package):
        if package.id in self.__dict_waiting_response.keys():
            return

        layer_DNSQR = package.getlayer(DNSQR)

        qname = layer_DNSQR.qname.decode()
        qtype = layer_DNSQR.qtype

        if qtype not in HANDLED_RECORD_TYPES:
            return

        _record = self.__get_record(qname, qtype)

        if _record is not None:
            send(package, _record)
        else:
            _id = self.__send_request(package)
            self.__dict_waiting_response[_id] = package

    def __handle_response(self, package):
        if not package.haslayer(DNSRR):
            return
        layer_DNSRR = package[DNSRR]

        for i in range(package[DNS].ancount):
            rname = layer_DNSRR[i].rrname.decode()
            rtype = layer_DNSRR[i].type

            if layer_DNSRR[i].type not in HANDLED_RECORD_TYPES:
                continue

            rdata = layer_DNSRR[i].rdata if type(layer_DNSRR[i].rdata) == str \
                else layer_DNSRR[i].rdata.decode()
            ttl = layer_DNSRR[i].ttl
            _record = record(rdata, package[DNS].aa, ttl, time.time() + ttl)

            if rname in self.__data_base.keys() and \
                    rtype in self.__data_base[rname]:
                self.__data_base[rname][rtype] = _record
            else:
                self.__data_base[rname] = {rtype: _record}

        self.__save_data_base()

        if package.getlayer(DNS).id in self.__dict_waiting_response.keys():
            _id = package.getlayer(DNS).id
            pkt = self.__dict_waiting_response[_id]
            self.__dict_waiting_response.pop(_id)
            self.__handle_request(pkt)

    def __send_request(self, package):
        org_layer_DNS = package.getlayer(DNS)

        package_request = \
            IP(dst=IP_DNS) / \
            UDP(dport=53) / \
            DNS(id=org_layer_DNS.id, qd=org_layer_DNS.qd)
        send(package_request, count=1)

        self.__log(
            'info', f'{IP_HOST} -> {IP_DNS}',
            prefixes=['request'],
            suffixes=[package.getlayer(DNSQR).qname.decode(),
                      package.getlayer(DNSQR).qtype])

        return package_request.getlayer(DNS).id

    def __send_response(self, package, _record):
        ip_src, ip_dst = DNSServer.__get_ip(package)
        layer_DNS = package.getlayer(DNS)
        layer_DNSQR = package.getlayer(DNSQR)
        qtype = layer_DNSQR.qtype

        send(IP(dst=ip_src) /
             UDP(dport=53) /
             DNS(id=layer_DNS.id,
                 qr=1,
                 rd=1,
                 ra=1,
                 qd=layer_DNS.qd,
                 an=DNSRR(rrname=layer_DNS.qd.qname,
                          type=qtype,
                          ttl=_record.ttl,
                          rdata=_record.data)),
             verbose=False)

        self.__log(
            'info', f'{IP_HOST} -> {ip_src}',
            prefixes=['response'])

    def __get_record(self, qname, qtype):
        if qname in self.__data_base and qtype in self.__data_base[qname]:
            return self.__data_base[qname][qtype]

        elif qname in self.__data_base and 5 in self.__data_base[qname]:
            return self.__get_record(self.__data_base[qname][5], qtype)

        return None

    def __log(self, _type, message, prefixes=None, suffixes=None):
        result = f'[{str(_type).upper()}] '

        if isinstance(prefixes, list) and len(prefixes) != 0:
            result += \
                ' '.join(f'[{str(p).upper()}]' for p in prefixes) + ' '

        result += str(message)

        if isinstance(suffixes, list) and len(suffixes) != 0:
            result += ' ' + ' '.join('{' + str(s) + '}' for s in suffixes)

        if self.__flag_debug:
            print(result)

        with open('log.txt', mode='a') as file_log:
            file_log.write(f'{result}\n')

    @staticmethod
    def __get_ip(package):
        if IP in package:
            return package[IP].src, package[IP].dst

        raise ValueError()


record = namedtuple('record', ('data', 'authority', 'ttl', 'time'))
