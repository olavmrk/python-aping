import asyncio
import contextlib
import ipaddress
import os
import random
import socket

from . import packet
from . import rawsocket

class PingResult(object):
    pass

class PingError(Exception):
    pass

class PingTransmitError(PingError):
    def __str__(self):
        return 'Transmit error: ' + str(self.__cause__)

class PingTimeoutError(PingError):
    def __init__(self):
        super().__init__('Timeout')

class PingTimeExceededError(PingError):
    def __init__(self, rtt, response):
        self.rtt = rtt
        self.source = response.source_address
        self.response = response
        super().__init__('TTL expired from {address}'.format(address=str(self.source)))

class PingDestinationUnreachableError(PingError):
    MESSAGES = {
        # IPv4 errors, from:
        # http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3
        (4,  0): 'Net Unreachable',
        (4,  1): 'Host Unreachable',
        (4,  2): 'Protocol Unreachable',
        (4,  3): 'Port Unreachable',
        (4,  4): 'Fragmentation Needed and Don\'t Fragment was Set',
        (4,  5): 'Source Route Failed',
        (4,  6): 'Destination Network Unknown',
        (4,  7): 'Destination Host Unknown',
        (4,  8): 'Source Host Isolated',
        (4,  9): 'Communication with Destination Network is Administratively Prohibited',
        (4, 10): 'Communication with Destination Host is Administratively Prohibited',
        (4, 11): 'Destination Network Unreachable for Type of Service',
        (4, 12): 'Destination Host Unreachable for Type of Service',
        (4, 13): 'Communication Administratively Prohibited',
        (4, 14): 'Host Precedence Violation',
        (4, 15): 'Precedence cutoff in effect',
        # IPv6 errors, from:
        # http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-2
        (6,  0): 'No route to destination',
        (6,  1): 'Communication with destination administratively prohibited',
        (6,  2): 'Beyond scope of source address',
        (6,  3): 'Address unreachable',
        (6,  4): 'Port unreachable',
        (6,  5): 'Source address failed ingress/egress policy',
        (6,  6): 'Reject route to destination',
        (6,  7): 'Error in Source Routing Header',
    }

    def __init__(self, rtt, response):
        self.rtt = rtt
        self.source = response.source_address
        self.protocol = response.version
        self.code = (response.version, response.extract_payload().code)
        self.response = response
        msg = PingDestinationUnreachableError.MESSAGES.get(self.code, 'Unknown error')
        msg = '[{protocol},{code}] {msg}'.format(protocol=self.code[0], code=self.code[1], msg=msg)
        super().__init__('Destination unreachable ({msg}) from {address}'.format(msg=msg, address=str(self.source)))

class PingResponse(PingResult):
    def __init__(self, rtt, response):
        self.rtt = rtt
        self.response = response


class PingEngine(object):

    def __init__(self):
        self._loop = asyncio.get_event_loop()
        self._rawsocket = rawsocket.RawSocket()

    def close(self):
        self._rawsocket.close()

    def _prepare_icmp(self, target, payload=b''):
        icmp = packet.IcmpEchoRequest()
        icmp.identifier = os.getpid() & 0xffff
        icmp.sequence_number = self._rawsocket.find_free_icmp_sequence_number(target, icmp.identifier)
        icmp.payload = payload
        icmp.calculate_checksum()
        target_tuple = (socket.IPPROTO_ICMP, target, icmp.identifier, icmp.sequence_number)
        return (target_tuple, icmp)

    def _prepare_tcp(self, target, source_port=None, destination_port=80):
        if source_port is None:
            source_port = random.randrange(32768, 33792)
        sequence_number = self._rawsocket.find_free_tcp_sequence_number(target, source_port, destination_port)
        tcp = packet.Tcp()
        tcp.source_port = source_port
        tcp.destination_port = destination_port
        tcp.sequence_number = sequence_number
        tcp.syn = True
        tcp.window_size = 2048
        tcp.calculate_checksum(self._rawsocket.get_source_address(target), target)
        target_tuple = (socket.IPPROTO_TCP, target, source_port, destination_port, sequence_number)
        return (target_tuple, tcp)

    def _prepare_ping(self, target, ttl, ping_type, **kwargs):
        if ping_type == 'icmp':
            target_tuple, payload = self._prepare_icmp(target, **kwargs)
        elif ping_type == 'tcp':
            target_tuple, payload = self._prepare_tcp(target, **kwargs)
        else:
            raise NotImplementedError('Unknown ping type: {ping_type}'.format(ping_type=ping_type))
        request_packet = packet.IPv4()
        request_packet.destination_address = target
        request_packet.time_to_live = ttl
        request_packet.embed_payload(payload)
        request_packet.calculate_checksum()
        request_packet = bytes(request_packet)
        return (target_tuple, request_packet)

    def ping(self, target, timeout=10.0, ttl=255, ping_type='icmp', **kwargs):
        if not isinstance(target, ipaddress.IPv4Address):
            raise ValueError('target must be a IPv4Address')

        target_tuple, request_packet = self._prepare_ping(target, ttl, ping_type, **kwargs)
        response_future = self._rawsocket.listener_future(target_tuple)
        try:
            sent = self._rawsocket.send(request_packet)
        except OSError as e:
            response_future.cancel()
            raise PingTransmitError() from e
        self._loop.call_later(timeout, response_future.cancel)
        try:
            received, response = yield from response_future
        except asyncio.CancelledError:
            raise PingTimeoutError() from None
        rtt = received - sent
        payload = response.extract_payload()
        if isinstance(payload, packet.IcmpTimeExceeded):
            raise PingTimeExceededError(rtt, response)
        elif isinstance(payload, packet.IcmpDestinationUnreachable):
            raise PingDestinationUnreachableError(rtt, response)
        else:
            return PingResponse(rtt, response)
