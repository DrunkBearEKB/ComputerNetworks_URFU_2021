import socket
import struct
import time
import sys


NTP_SERVER = 'localhost'  # 1. localhost  2. 0.uk.pool.ntp.org
TIME1970 = 2208988800


if __name__ == '__main__':
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = '\x1b' + 47 * '\0'
        client.sendto(data.encode('utf-8'), (NTP_SERVER, 124))
        print('Sended!')
        data, address = client.recvfrom(1024)
        print(f'data = {data}, {len(data)}')
        print(f'# {struct.unpack("!12I", data)}')
        print(data[-32:-24], data[-24:-16], data[-16:-8], data[-8:])
        print(data[-32:-24], data[-24:-16], data[-16:-8], data[-8:])

# server
# b'$\x01\x04\xe7\x00\x00\x00\x00\x00\x00\x00\x00GPS\x00\xe3\xee\x7f7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe3\xee\x7f7LS\x93\xc1\xe3\xee\x7f7LS\xf3\xcd'
# (469959656, 442, 1529, 3791317199, 3824080028, 3102933715, 0, 0, 3824080527, 2874918680, 3824080527, 2874999946)
# b'\xe3\xee\xd6\xba6$\x81\xb1' - b'\x00\x00\x00\x00\x00\x00\x00\x00' - b'\xe3\xee\xd7\xd0\x93\x0fN=' - b'\xe3\xee\xd7\xd0\x93\x10\xe6c'

# my
# b'\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`C\xe9\x0f\x00\x00\x00\x00\x00\x00\x00\x00`D\x00u`D\x00u'
        t = struct.unpack('!12I', data)[10] - TIME1970
        print(t)
        if data:
            print(f'Response received from: {address[0]} [{NTP_SERVER}]\n'
                  f'Time: {time.ctime(t).replace("  ", " ")}')

    except KeyboardInterrupt:
        sys.exit(2)
