import sys
import argparse

from DNSServer import DNSServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true',
                        help='enable debug on')
    parser.add_argument('-i', '--intercept', action='store_true',
                        help='toggle intercept mode')
    args = parser.parse_args()

    dns_server = DNSServer(flag_debug=args.debug,
                           flag_intercept_mode=args.intercept)
    dns_server.start()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(-1)
