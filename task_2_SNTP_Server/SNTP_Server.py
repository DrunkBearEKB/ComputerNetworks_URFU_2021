import configparser
import os
import sys
import time
import socket
import struct


TIME_OFFSET_DEFAULT = 100


def main():
    config = configparser.ConfigParser()
    if not os.path.exists('config.ini'):
        config['Settings'] = {
            'time_offset': f'{TIME_OFFSET_DEFAULT}',
            'port': f'{123}'}

        with open('config.ini', 'w') as file_config:
            config.write(file_config)

    config.read('config.ini')
    try:
        time_offset = config['Settings']['time_offset']
        host_port = int(config['Settings']['port'])
    except (KeyError, ValueError):
        config.clear()
        config['Settings'] = {
            'time_offset': f'{TIME_OFFSET_DEFAULT}',
            'port': f'{123}'}

        with open('config.ini', 'w') as file_config:
            config.write(file_config)

        time_offset = TIME_OFFSET_DEFAULT
        host_port = 123

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', host_port))
    time_started = time.time()

    print(f'Started at (localhost, {host_port})')
    while True:
        data_received, address = sock.recvfrom(1024)
        time_received = time.time()
        print(f'{address[0]} connected!\n\tData: {data_received}')
        # pattern = '!Q'
        # print(struct.pack(pattern, int(time_started)),
        #       struct.pack(pattern, int(time_received)),
        #       struct.pack(pattern, int(time.time())))
        # data = b'\x1c' + \
        #        15 * b'\x00' + \
        #        struct.pack(pattern, int(time_started)) + \
        #        8 * b'\x00' + \
        #        struct.pack(pattern, int(time_received)) + \
        #        struct.pack(pattern, int(time.time()))
        pattern = "!BBBb11I"
        data = struct.pack(pattern, b'')

        sock.sendto(data, address)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(-1)
