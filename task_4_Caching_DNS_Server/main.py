import sys
import argparse

from DNSServer import DNSServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', help='')
    args = parser.parse_args()

    dns_server = DNSServer(debug=True)
    dns_server.start()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(-1)
