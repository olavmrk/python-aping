import asyncio
import collections
import ipaddress
import random
import socket
import struct
import time

from . import packet

class _ReceiveDispatcher(object):

    def __init__(self):
        self._listeners = collections.defaultdict(lambda: collections.defaultdict(set))

    def _attach_listener(self, ip_target, protocol_target, callback):
        self._listeners[ip_target][protocol_target].add(callback)

    def _detach_listener(self, ip_target, protocol_target, callback):
        self._listeners[ip_target][protocol_target].remove(callback)
        if not self._listeners[ip_target][protocol_target]:
            del self._listeners[ip_target][protocol_target]
        if not self._listeners[ip_target]:
            del self._listeners[ip_target]

    def _has_listener(self, ip_target, protocol_target):
        if not ip_target in self._listeners:
            return False
        if not protocol_target in self._listeners[ip_target]:
            return False
        return True

    @staticmethod
    def _icmp_target(remote_address, identifier, sequence_number):
        ip_target = (remote_address.packed, 1)
        icmp_target = struct.pack('>HH', identifier, sequence_number)
        return ip_target, icmp_target

    @staticmethod
    def _tcp_target(remote_address, local_port, remote_port, sequence_number):
        ip_target = (remote_address.packed, 6)
        expected_ack = (sequence_number + 1) & 0xffffffff
        tcp_target = struct.pack('>HHI', remote_port, local_port, expected_ack)
        return ip_target, tcp_target

    @staticmethod
    def _split_target(target):
        if target[0] == socket.IPPROTO_ICMP:
            return _ReceiveDispatcher._icmp_target(target[1], target[2], target[3])
        elif target[0] == socket.IPPROTO_TCP:
            return _ReceiveDispatcher._tcp_target(target[1], target[2], target[3], target[4])
        else:
            raise NotImplementedError()

    def listener_future(self, target):
        ip_target, protocol_target = _ReceiveDispatcher._split_target(target)
        future = asyncio.Future()
        self._attach_listener(ip_target, protocol_target, future.set_result)
        def _cleanup(future):
            self._detach_listener(ip_target, protocol_target, future.set_result)
        future.add_done_callback(_cleanup)
        return future

    def _dispatch_target(self, ip_target, protocol_target, raw_packet, timestamp):
        ip_listeners = self._listeners.get(ip_target, None)
        if ip_listeners is None:
            return
        protocol_listeners = ip_listeners.get(protocol_target, None)
        if protocol_listeners is None:
            return
        try:
            response = packet.IPv4.from_bytes(raw_packet)
            payload = response.extract_payload()
        except:
            return # Invalid response
        for target in protocol_listeners:
            target((timestamp, response))

    def _dispatch_icmp_echo(self, raw_packet, timestamp, ip_target, icmp_start):
        icmp_match = raw_packet[icmp_start+4:icmp_start+8]
        return self._dispatch_target(ip_target, icmp_match, raw_packet, timestamp)

    def _dispatch_tcp(self, raw_packet, timestamp, ip_target, tcp_start):
        if len(raw_packet) < tcp_start + 12:
            return # Too short to contain enough data from the TCP header to route it.
        port_match = raw_packet[tcp_start:tcp_start+4] # b'<remote_port><local_port>'
        ack_match = raw_packet[tcp_start+8:tcp_start+12]
        tcp_match = port_match + ack_match
        return self._dispatch_target(ip_target, tcp_match, raw_packet, timestamp)

    def _dispatch_tcp_error(self, raw_packet, timestamp, ip_target, tcp_start):
        if len(raw_packet) < tcp_start + 8:
            return # Too short to contain 8 bytes of the original TCP header
        # For fast matching of incoming TCP datagrams, the match block
        # for TCP is b'<remote_port><local_port><expected_ack>'
        # Now we need to transform our outgoing datagram into this form.
        local_port_bytes = raw_packet[tcp_start:tcp_start+2]
        remote_port_bytes = raw_packet[tcp_start+2:tcp_start+4]
        sequence_number_bytes = raw_packet[tcp_start+4:tcp_start+8]
        sequence_number = struct.unpack('>I', sequence_number_bytes)[0]
        expected_ack = (sequence_number + 1) & 0xffffffff
        expected_ack_bytes = struct.pack('>I', expected_ack)
        tcp_match = remote_port_bytes + local_port_bytes + expected_ack_bytes
        return self._dispatch_target(ip_target, tcp_match, raw_packet, timestamp)

    def _dispatch_ipv4_icmp_error_icmp(self, raw_packet, timestamp, ip_target, icmp_start):
        if len(raw_packet) < icmp_start + 8:
            return # Too short to contain 8 bytes of the original ICMP header
        icmp_type = raw_packet[icmp_start]
        if icmp_type != 8:
            return # Not a transmitted echo request
        return self._dispatch_icmp_echo(raw_packet, timestamp, ip_target, icmp_start)

    def _dispatch_ipv4_icmp_error(self, raw_packet, timestamp, icmp_start):
        ip_start = icmp_start + 8
        if len(raw_packet) < ip_start + 20:
            return # Too short to contain the inner IP header
        remote_address = raw_packet[ip_start+16:ip_start+20]
        protocol = raw_packet[ip_start + 9]
        ip_target = (remote_address, protocol)
        protocol_start = ip_start + (raw_packet[ip_start] & 0b00001111) * 4
        if protocol == 1:
            return self._dispatch_ipv4_icmp_error_icmp(raw_packet, timestamp, ip_target, protocol_start)
        elif protocol == 6:
            return self._dispatch_tcp_error(raw_packet, timestamp, ip_target, protocol_start)

    def _dispatch_ipv4_icmp(self, raw_packet, timestamp, ip_target, icmp_start):
        if len(raw_packet) < icmp_start + 8:
            return # Too short to contain the 8-byte ICMP header
        icmp_type = raw_packet[icmp_start]
        if icmp_type == 0:
            return self._dispatch_icmp_echo(raw_packet, timestamp, ip_target, icmp_start)
        elif icmp_type == 3: # Destination unreachable
            return self._dispatch_ipv4_icmp_error(raw_packet, timestamp, icmp_start)
        elif icmp_type == 11: # Time exceeded
            return self._dispatch_ipv4_icmp_error(raw_packet, timestamp, icmp_start)
        else:
            return # Unknown ICMP type

    def _dispatch_ipv4(self, raw_packet, timestamp):
        if len(raw_packet) < 20:
            return # Too short to contain the full IPv4 header
        protocol = raw_packet[9]
        protocol_start = (raw_packet[0] & 0b00001111) * 4
        remote_address = raw_packet[12:16]
        ip_target = (remote_address, protocol)
        if protocol == 1:
            return self._dispatch_ipv4_icmp(raw_packet, timestamp, ip_target, protocol_start)
        elif protocol == 6:
            return self._dispatch_tcp(raw_packet, timestamp, ip_target, protocol_start)
        else:
            return # Protocol not implemented

    def dispatch(self, raw_packet, timestamp):
        if len(raw_packet) < 1:
            return # Not enough data to identify packet
        ip_protocol = (raw_packet[0] >> 4)
        if ip_protocol == 4:
            return self._dispatch_ipv4(raw_packet, timestamp)
        else:
            return # Protocol not implemented

    def find_free_icmp_sequence_number(self, target, identifier):
        while True:
            sequence_number = random.randrange(0x10000)
            ip_target, protocol_target = _ReceiveDispatcher._icmp_target(target, identifier, sequence_number)
            if self._has_listener(ip_target, protocol_target):
                # Something else is already using this sequence number
                continue
            return sequence_number

    def find_free_tcp_sequence_number(self, target, source_port, destination_port):
        while True:
            sequence_number = random.randrange(0x100000000)
            ip_target, protocol_target = _ReceiveDispatcher._tcp_target(target, source_port, destination_port, sequence_number)
            if self._has_listener(ip_target, protocol_target):
                # Something else is already using this sequence number
                continue
            return sequence_number


class _RawReceiver(object):

    def __init__(self, dispatcher):
        self._dispatcher = dispatcher
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
        self._dispatcher = _ReceiveDispatcher()
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
