import asyncio
import collections
import contextlib
import ipaddress
import os
import random
import socket
import time

from . import packet

class PingResult(object):
    pass

class PingError(Exception):
    pass

class PingTimeoutError(PingError):
    def __init__(self):
        super().__init__('Timeout')

class PingTimeExceededError(PingError):
    def __init__(self, rtt, response):
        self.rtt = rtt
        self.source = response.source_address
        self.response = response
        super().__init__('TTL expired from {address}'.format(address=str(self.source)))

class PingResponse(PingResult):
    def __init__(self, rtt, response):
        self.rtt = rtt
        self.response = response


class PingEngine(object):

    def __init__(self):
        self._loop = asyncio.get_event_loop()
        self._receive_monitors = {}
        self._transmit_sockets = {}
        self._listeners = collections.defaultdict(set)

    def close(self):
        for monitor in self._receive_monitors.values():
            monitor.cancel()
        for sock in self._transmit_sockets.values():
            sock.close()

    def _ensure_receiver(self, family, protocol):
        key = (family, protocol)
        if key in self._receive_monitors:
            return
        sock = socket.socket(family, socket.SOCK_RAW, protocol)
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        monitor = self._loop.create_task(self._monitor_socket(sock))
        self._receive_monitors[key] = monitor

    def _get_transmit_socket(self, family):
        if not family in self._transmit_sockets:
            # No socket present -- create one
            sock = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setblocking(False)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._transmit_sockets[family] = sock
        return self._transmit_sockets[family]

    def _listener_future(self, target):
        # Make sure that we are ready to receive packets from this target.
        protocol = target[0]
        self._ensure_receiver(socket.AF_INET, protocol)
        if protocol != socket.IPPROTO_ICMP:
            # If the protocol is TCP or UDP, we may receive
            # errors using the ICMP Protocol
            self._ensure_receiver(family, socket.IPPROTO_ICMP)

        future = asyncio.Future()
        # Attach the queue to the packet listeners
        self._listeners[target].add(future)
        def _cleanup(future):
            self._listeners[target].remove(future)
            if not self._listeners[target]:
                # Nothing else listening for this target -- clean it up
                del self._listeners[target]
        future.add_done_callback(_cleanup)
        return future

    def _lookup(self, target):
        return self._listeners[target]

    def _lookup_icmp(self, source_address, identifier, sequence_number):
        target = (socket.IPPROTO_ICMP, source_address, identifier, sequence_number)
        return self._lookup(target)

    def _find_inner_payload_futures(self, outer_payload):
        try:
            protocol_header = outer_payload.extract_payload()
            address = protocol_header.destination_address
            payload = protocol_header.extract_payload(allow_partial=True)
        except:
            # Not enough data in the packet to identify it.
            return set()
        # Now we have the payload we just sent in `payload` and its destination in
        # address. Find out what kind of packet this was and try to match it to our
        # listeners.
        if isinstance(payload, packet.IcmpEchoRequest):
            return self._lookup_icmp(address, payload.identifier, payload.sequence_number)
        else:
            return set() # Unknown payload type

    def _find_payload_futures(self, source_address, payload):
        if isinstance(payload, packet.IcmpEchoReply):
            return self._lookup_icmp(source_address, payload.identifier, payload.sequence_number)
        elif isinstance(payload, packet.IcmpTimeExceeded):
            return self._find_inner_payload_futures(payload)
        else:
            return set() # Unknown payload type

    @asyncio.coroutine
    def _monitor_socket(self, sock):
        try:
            while True:
                response = yield from self._loop.sock_recv(sock, 65536)
                ts = time.clock_gettime(time.CLOCK_MONOTONIC)
                try:
                    response = packet.IPv4.from_bytes(response)
                    payload = response.extract_payload()
                except:
                    continue # Invalid response
                futures = self._find_payload_futures(response.source_address, payload)
                for future in futures:
                    future.set_result((ts, response))
        finally:
            sock.close()

    def _prepare_icmp(self, target, identifier=None, sequence_number=None, payload=b''):
        if identifier is None:
            identifier = os.getpid() & 0xffff
        if sequence_number is None:
            while True:
                sequence_number = random.randrange(0x10000)
                if self._lookup_icmp(target, identifier, sequence_number):
                    # Something else is already using this sequence number
                    continue
                break
        icmp = packet.IcmpEchoRequest()
        icmp.identifier = identifier
        icmp.sequence_number = sequence_number
        icmp.payload = payload
        icmp.calculate_checksum()
        target_tuple = (socket.IPPROTO_ICMP, target, identifier, sequence_number)
        return (target_tuple, icmp)

    def _prepare_ping(self, target, ttl, ping_type, **kwargs):
        if ping_type == 'icmp':
            target_tuple, payload = self._prepare_icmp(target, **kwargs)
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
        response_future = self._listener_future(target_tuple)
        sock = self._get_transmit_socket(socket.AF_INET)
        sock.sendto(request_packet, (str(target), 0))
        sent = time.clock_gettime(time.CLOCK_MONOTONIC)
        self._loop.call_later(timeout, response_future.cancel)
        try:
            received, response = yield from response_future
        except asyncio.CancelledError:
            raise PingTimeoutError() from None
        rtt = received - sent
        payload = response.extract_payload()
        if isinstance(payload, packet.IcmpTimeExceeded):
            raise PingTimeExceededError(rtt, response)
        else:
            return PingResponse(rtt, response)
