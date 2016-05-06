#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import socket
import sys

import aping

def parse_args():
    parser = argparse.ArgumentParser(description='Ping a host')
    parser.add_argument('target', help='Target host')
    parser.add_argument('--ttl', type=int, default=255, help='TTL on sent packets')
    return parser.parse_args()

def lookup(target):
    try:
        address = socket.getaddrinfo(target, 0, family=socket.AF_INET)
    except socket.gaierror as e:
        print('Error looking up {host}: {err}'.format(host=target, err=str(e)), file=sys.stderr)
        sys.exit(1)
    address = address[0][4][0]
    return address

def main():
    args = parse_args()
    address = lookup(args.target)
    print('Sending ping to {host} [{address}]:'.format(host=args.target, address=address))
    loop = asyncio.get_event_loop()
    try:
        result = loop.run_until_complete(aping.ping(ipaddress.ip_address(address), timeout=1, ttl=args.ttl))
        print('Got response in {rtt:.2f} ms'.format(rtt=result.rtt*1000))
    except aping.PingError as e:
        print('Error:', e)

if __name__ == '__main__':
    main()
