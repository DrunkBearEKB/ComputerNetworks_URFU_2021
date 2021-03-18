import socket
import argparse
import os
import datetime
import sys
import time
import collections

HOST = '127.0.0.1'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--progress', action='store_true',
                        help='shows the progress during the check')
    parser.add_argument('-s', '--save', action='store_true',
                        help='saves the results to a file')
    parser.add_argument('--timeouttcp', action='store', type=float, nargs='?',
                        help='sets the timeout for tcp')
    parser.add_argument('--timeoutudp', action='store', type=float, nargs='?',
                        help='sets the timeout for udp')
    parser.add_argument('start', type=int, default=1, nargs='?',
                        help='lower bound of port validation')
    parser.add_argument('end', type=int, default=65535, nargs='?',
                        help='upper bound of port validation')
    args = parser.parse_args()

    timeout_tcp = 0.01 if args.timeouttcp is None else args.timeouttcp
    timeout_udp = 0.005 if args.timeoutudp is None else args.timeoutudp

    warning = collections.namedtuple('Warning', ['Port', 'Exception', 'Time'])
    dict_warnings = {'INPUT': list(), 'TCP': list(), 'UDP': list()}

    if args.start < 1:
        message = f'[WARNING] The port number cannot be negative and zero! ' \
                  f'It will be equaled to 1!'
        print(message)
        dict_warnings['INPUT'].append(message)
        port_start = 1
    else:
        port_start = args.start

    if args.end > 65535:
        message = f'[WARNING] The port number cannot be greater than 65535! ' \
                  f'It will be equated to 65535!'
        print(message)
        dict_warnings['INPUT'].append(message)
        port_end = 65535
    else:
        port_end = args.end

    dict_port_protocol = {}

    dict_ports_used = {'TCP': list(), 'UDP': list()}

    progress = 0
    amount = 50
    _len = port_end - port_start

    time_started = time.time()
    if args.progress:
        print('\rProgress: [' + ' ' * amount + '] 0% - Left: inf seconds',
              end='')

    for port in range(port_start, port_end + 1):
        if args.progress and (port - port_start) / _len >= \
                (progress + 1) / amount:
            progress += 1
            time_temp = round((amount / progress - 1) *
                              (time.time() - time_started), 1)
            print(
                f'\rProgress: [' + '#' * progress + ' ' * (amount - progress) +
                f'] {int(progress / amount * 100)}% - Left: '
                f'{time_temp} seconds                  ', end='')

        # TCP
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.settimeout(timeout_tcp)
        try:
            sock_tcp.connect((HOST, port))
            dict_ports_used['TCP'].append(port)
            sock_tcp.close()
        except socket.timeout:
            pass
        except OSError:
            pass
        except Exception as exception:
            dict_warnings['TCP'].append(
                warning(port, exception, datetime.datetime.now()))

        # UDP
        sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_udp.settimeout(timeout_udp)
        try:
            code = sock_udp.connect_ex((HOST, port))
            sock_udp.close()
            if code == 0:
                dict_ports_used['UDP'].append(port)
        except socket.timeout:
            pass
        except OSError:
            pass
        except Exception as exception:
            dict_warnings['TCP'].append(warning(port, exception,
                                                datetime.datetime.now()))

        try:
            dict_port_protocol[port] = socket.getservbyport(port)
        except OSError:
            pass

    if args.progress:
        print(
            f'\rProgress: [' + '#' * amount +
            f'] Finished for {round(time.time() - time_started, 1)} '
            f'seconds!              ')

    content = ''
    for key, _list in dict_ports_used.items():
        content += \
            f'Opened {key} ports from {port_start} to {port_end}:\n'
        if len(_list) > 0:
            list_accumulated_ports = list()
            list_str = list()
            for port in _list:
                if type(port) == str:
                    if len(list_accumulated_ports) not in [0, 1]:
                        list_str.append(
                            f'{list_accumulated_ports[0]} - '
                            f'{list_accumulated_ports[-1]}')
                    elif len(list_accumulated_ports) == 1:
                        list_str.append(str(list_accumulated_ports[0]))
                    list_accumulated_ports.clear()
                    list_str.append(port)
                elif len(list_accumulated_ports) == 0:
                    list_accumulated_ports.append(port)
                elif port == list_accumulated_ports[-1] + 1:
                    list_accumulated_ports.append(port)
                else:
                    if len(list_accumulated_ports) != 1:
                        list_str.append(
                            f'{list_accumulated_ports[0]} - '
                            f'{list_accumulated_ports[-1]}')
                    else:
                        list_str.append(str(list_accumulated_ports[0]))
                    list_accumulated_ports.clear()

            if len(list_accumulated_ports) != 0:
                if len(list_accumulated_ports) != 1:
                    list_str.append(
                        f'{list_accumulated_ports[0]} - '
                        f'{list_accumulated_ports[-1]}')
                else:
                    list_str.append(str(list_accumulated_ports[0]))

            content += ', '.join(_str for _str in list_str)
        else:
            content += 'None'

        content += ';\n\n'

    if len(dict_port_protocol) != 0:
        content += 'Protocols running on ports:\n'
        counter = 0
        counter_max = 2
        for port, protocol in dict_port_protocol.items():
            content += ' ' * (5 - len(str(port))) + f'{port}: ' + \
                       ' ' * (20 - len(protocol)) + str(protocol) + ' '
            counter += 1
            if counter == counter_max:
                counter = 0
                content += '\n'

    if args.save:
        if not os.path.exists('ports_scanning_results'):
            os.mkdir('ports_scanning_results')
        os.chdir('ports_scanning_results')
        datetime_now = str(datetime.datetime.now()) \
            .replace(' ', '-').replace(':', '-')
        _time = datetime_now[:datetime_now.index('.')]
        file_name = \
            f'port_scanning_[{port_start}-{port_end}]_[{_time}]'

        try:
            with open(file_name, mode='w+') as file_results:
                content_warning = ''
                for key, _list in dict_warnings.items():
                    if len(_list) != 0:
                        content_warning += f'[WARNINGS {key}]\n'
                        if key != 'INPUT':
                            content_warning += \
                                '\n'.join(f'Port: {w.Port}; '
                                          f'Exception: {w.Exception}; '
                                          f'Time: {w.Time}' for w in _list)
                        else:
                            content_warning += '\n'.join(f'{w}' for w in _list)
                file_results.write(
                    content + ('\n' * 2 + content_warning
                               if len(content_warning) != 0 else ''))
            os.chdir('..')
            return
        except Exception:
            print(f'[ERROR] Can not save results in file {file_name}! '
                  f'Results will be printed.')

    print(content)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(-1)
