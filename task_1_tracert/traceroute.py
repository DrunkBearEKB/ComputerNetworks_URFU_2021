import sys
import socket
import random
import time
import argparse
import urllib.request


TIMEOUT = 500
AMOUNT_HOPS = 30
AMOUNT_TRIES = 10
AMOUNT_COLUMNS = 3
URL_AS = 'https://www.nic.ru/whois/?ipartner=3522&adv_id=41&utm_source=yand' \
         'exdirect&utm_medium=cpc&utm_campaign=33_-_whois_russia_search&utm' \
         '_content=%7Cc%3A16061145%7Cg%3A1146178723%7Cb%3A1583205103%7Ck%3A' \
         '4863537821%7Cst%3Asearch%7Ca%3Ano%7Cs%3Anone%7Ct%3Apremium%7Cp%3A' \
         '1%7Cr%3A%7Cdev%3Adesktop&yclid=1027230008720776462&searchWord='


def check_input_validity(_input):
    try:
        input_parsed = list(map(int, _input.split('.')))

        if len(input_parsed) != 4:
            return False, None
        input_parsed = list(map(lambda x: 0 <= x <= 255, input_parsed))

        if all(input_parsed):
            return True, socket.gethostbyname(_input)

    except ValueError:
        try:
            host_name = socket.gethostbyname(_input)
            return True, host_name

        except socket.gaierror:
            return False, None


def send(ip_target, package_ttl, show_time=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, package_ttl)
    sock.settimeout(TIMEOUT / 1000)

    results = [False, [], []]

    for i in range(AMOUNT_COLUMNS):
        for j in range(AMOUNT_TRIES):
            icmp_id = random.randint(0, 2 ** 16 - 1)
            _sum = checksum(b'\x08\x00\x00\x00' + icmp_id.to_bytes(2, 'big') +
                            b'\x00\x01')
            data = b'\x08\x00' + socket.htons(_sum).to_bytes(2, 'little') + \
                   icmp_id.to_bytes(2, 'big') + b'\x00\x01'
            sock.sendto(data, (ip_target, 0))

            time_started = time.time()
            try:
                data_received, address = sock.recvfrom(2 ** 10)
                id_received = int.from_bytes(data_received[-4:-2], 'big')
                if id_received == icmp_id:
                    results[0] = True

                    if show_time:
                        temp = int((time.time() - time_started) * 1000)
                        results[1].append(temp if temp >= 1 else '<1')

                    try:
                        with urllib.request.urlopen(URL_AS + address[0]) as fp:
                            _bytes = fp.read()
                            html_code = _bytes.decode('utf8')

                        href_start = '_3U-mA _23Irb'
                        try:
                            index_start = html_code.index(href_start) + \
                                          len(href_start) + 2
                            index_end = html_code[index_start:].index('</div>')
                        except ValueError:
                            index_start = 0
                            index_end = len(html_code)
                        html_code = html_code[index_start:
                                              index_start + index_end]

                        res = {}
                        for line in html_code.split('\n'):
                            if ':' in line:
                                _index = line.index(':')
                                if 'orig' in line[:_index] and \
                                        'AS' in line[_index + 1:]:
                                    res['AS'] = line[_index + 1:]\
                                        .lstrip().rstrip().replace('AS', '')

                                if 'ountr' in line[:_index]:
                                    res['Country'] = line[_index + 1:] \
                                        .lstrip().rstrip()
                                    if ' ' in res['Country']:
                                        res['Country'] = res['Country'][
                                                         res['Country']:]

                                if 'descr' in line[:_index]:
                                    res['Provider'] = line[_index + 1:] \
                                        .lstrip().rstrip()
                        if 'AS' not in res.keys():
                            if 'Country' in res.keys():
                                res.pop('Country')
                            if 'Provider' in res.keys():
                                res.pop('Provider')

                        results[2] = [address[0]] + \
                                     [f'{k}: {v}' for k, v in res.items()]
                        results[2].sort()

                    except Exception:
                        results[2] = [address[0]]

                    if address[0] == ip_target:
                        results[0] = None
                        return results
                    break

            except socket.timeout:
                pass

        if not results[0]:
            results[1].append(f'*')
            results[2] = None

    sock.close()

    if results[0]:
        return results[0], results[1], results[2]

    return False, None, None


def checksum(_bytes):
    _sum = 0
    count_start = 0
    count_end = (len(_bytes) / 2) * 2

    while count_start < count_end:
        this_val = (_bytes[count_start + 1]) * 2 ** 8 + (_bytes[count_start])
        _sum = _sum + this_val
        _sum = _sum & 0xffffffff
        count_start = count_start + 2

    if count_end < len(_bytes):
        _sum = _sum + (_bytes[len(_bytes) - 1])
        _sum = _sum & 0xffffffff

    _sum = (_sum >> 16) + (_sum & 0xffff)
    _sum = _sum + (_sum >> 16)
    result = ~_sum
    result = result & 0xffff
    result = result >> 8 | (result << 8 & 0xff00)

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--time', action='store_true',
                        help='displays the results of time intervals '
                             'in three columns')
    parser.add_argument('-c', '--clear', action='store_true',
                        help='clears the console screen before '
                             'displaying the result')
    parser.add_argument('ip', help='ip address or domain name')
    args = parser.parse_args()

    if args.clear:
        import os
        temp = os.system('cls')
        del temp, os

    _input = args.ip
    validity, target = check_input_validity(_input)
    if not validity:
        print(f'ERROR: {sys.argv[1]} - Incorrect IP address!')
        sys.exit(2)

    print(
        f'Tracing the route to '
        f'{_input} {"" if _input == target else f"[{target}] "}'
        f'with a maximum number of hops {AMOUNT_HOPS}:')

    for i in range(AMOUNT_HOPS):
        flag_successful, send_results, options = \
            send(target, i + 1, show_time=args.time)

        print(' ' * (3 - len(str(i + 1))) + str(i + 1), end=' ')
        if flag_successful is None:
            for res in send_results:
                print(' ' * (5 - len(str(res))) + f'{res} ms', end=' ')

            print(' ' + ' '.join(f'[{opt}]' for opt in options))
            return

        elif flag_successful:
            for res in send_results:
                print(' ' * (5 - len(str(res))) + f'{res} ms', end=' ')

            print(' ' + ' '.join(f'[{opt}]' for opt in options))

        else:
            if args.time:
                print(' ' + '    *    ' * AMOUNT_COLUMNS +
                      f'The waiting interval for the '
                      f'request has been exceeded.')
            else:
                print(f' The waiting interval for the '
                      f'request has been exceeded.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(-1)
