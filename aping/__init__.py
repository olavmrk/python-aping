import asyncio
import ipaddress
import socket

from .packet import (Icmp, IcmpEchoRequest, IPv4, Tcp)
from .engine import PingEngine, PingError

@asyncio.coroutine
def ping(target, **kwargs):
    engine = PingEngine()
    try:
        result = yield from engine.ping(target, **kwargs)
    finally:
        engine.close()
    return result

@asyncio.coroutine
def ping_old(target):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    #sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setblocking(False)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #sock.connect( (target, 0) )
    sock.bind( ('0.0.0.0', 12345) )
    request = IcmpEchoRequest()
    request.payload = b'Hello World!'
    request.calculate_checksum()
    ipv4 = IPv4()
    ipv4.destination_address = ipaddress.IPv4Address(target)
    ipv4.time_to_live = 4
    ipv4.embed_payload(request)
    sock.sendto(bytes(ipv4), (target, 0))
    loop = asyncio.get_event_loop()
    while True:
        response = yield from loop.sock_recv(sock, 65536)
        response = IPv4.from_bytes(response)
        payload = response.extract_payload()
        if isinstance(payload, Tcp) and payload.destination_port == 22 or payload.source_port == 22:
            continue
        print(response)
        print(payload)
        print()

