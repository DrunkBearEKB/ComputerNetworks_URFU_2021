from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.dns import DNS, DNSRR, DNSQR


HOST = '192.168.88.159'


class DNSServer:
    def __init__(self, debug=False):
        self._flag_debug = debug

    def start(self):
        self.__load_data_base()

        self.__log(f'Server started at [{datetime.now()}]')

        while True:
            sniff(filter='udp and port 53', store=0,
                  prn=lambda pkt: self.__sniff(pkt))

    def __load_data_base(self):
        pass

    def __sniff(self, pkt):
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst

            if pkt.haslayer(DNS):
                if pkt.getlayer(DNS).qr == 0:  # обработка запроса
                    layer_DNSQR = pkt.getlayer(DNSQR)

                    self.__log(
                        f'{ip_src} <<< {ip_dst} | '
                        f'qname={layer_DNSQR.qname} : '
                        f'qtype={layer_DNSQR.qtype} : '
                        f'qclass={layer_DNSQR.qclass}')

                else:  # обработка ответа
                    layer_DNSRR = pkt.getlayer(DNSRR)

                    self.__log(
                        f'{ip_dst} >>> {ip_src} | '
                        f'')

    def __parse_qtype(self, qtype):
        if qtype == 1:  # A
            return
        if qtype == 28:  # AAAA
            return
        if qtype == 2:  # NS
            return
        if qtype == 12:  # PTR
            return

    def __log(self, message):
        if self._flag_debug:
            print(f'[DEBUG] {message}')



