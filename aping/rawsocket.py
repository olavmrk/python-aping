import asyncio
import collections
import ipaddress
import socket
import time

from . import dispatcher
from . import packet

class _RawReceiver(object):

    def __init__(self, _dispatcher):
        self._dispatcher = _dispatcher
        self._loop = asyncio.get_event_loop()
        self._receive_sockets = {}

    def close(self):
        for receive_socket in self._receive_sockets.values():
            self._loop.remove_reader(receive_socket.fileno())
            receive_socket.close()

    def ensure_receiver(self, family, protocol):
        key = (family, protocol)
        if key in self._receive_sockets:
            return
        sock = socket.socket(family, socket.SOCK_RAW, protocol)
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self._loop.add_reader(sock.fileno(), self._receive, sock)
        self._receive_sockets[key] = sock

    def _receive(self, sock):
        response = sock.recv(65536)
        ts = time.clock_gettime(time.CLOCK_MONOTONIC)
        self._dispatcher.dispatch(response, ts)


class RawSocket(object):

    def __init__(self):
        self._loop = asyncio.get_event_loop()
        self._dispatcher = dispatcher.ReceiveDispatcher()
        self._receiver = _RawReceiver(self._dispatcher)
        self._transmit_sockets = {}
        self._listeners = collections.defaultdict(set)

    def close(self):
        self._receiver.close()
        for sock in self._transmit_sockets.values():
            sock.close()

    def _get_transmit_socket(self, family):
        if not family in self._transmit_sockets:
            # No socket present -- create one
            sock = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setblocking(False)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._transmit_sockets[family] = sock
        return self._transmit_sockets[family]

    def listener_future(self, target):
        # Make sure that we are ready to receive packets from this target.
        protocol = target[0]
        self._receiver.ensure_receiver(socket.AF_INET, protocol)
        if protocol != socket.IPPROTO_ICMP:
            # If the protocol is TCP or UDP, we may receive
            # errors using the ICMP Protocol
            self._receiver.ensure_receiver(socket.AF_INET, socket.IPPROTO_ICMP)
        return self._dispatcher.listener_future(target)

    def get_source_address(self, target):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect( (str(target), 0) )
            source_address, source_port = s.getsockname()
            return ipaddress.ip_address(source_address)

    def find_free_icmp_sequence_number(self, target, identifier):
        return self._dispatcher.find_free_icmp_sequence_number(target, identifier)

    def find_free_tcp_sequence_number(self, target, source_port, destination_port):
        return self._dispatcher.find_free_tcp_sequence_number(target, source_port, destination_port)

    def send(self, raw_packet):
        destination_address = raw_packet[16:20]
        destination_address = ipaddress.IPv4Address(destination_address)
        destination_address = str(destination_address)
        sock = self._get_transmit_socket(socket.AF_INET)
        sock.sendto(raw_packet, (destination_address, 0))
        sent = time.clock_gettime(time.CLOCK_MONOTONIC)
        return sent
