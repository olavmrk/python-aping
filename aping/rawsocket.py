import asyncio
import collections
import ipaddress
import random
import socket
import time

from . import packet

class RawSocket(object):

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

    def listener_future(self, target):
        # Make sure that we are ready to receive packets from this target.
        protocol = target[0]
        self._ensure_receiver(socket.AF_INET, protocol)
        if protocol != socket.IPPROTO_ICMP:
            # If the protocol is TCP or UDP, we may receive
            # errors using the ICMP Protocol
            self._ensure_receiver(socket.AF_INET, socket.IPPROTO_ICMP)

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
        # We manually check for the presence of `target` here in order to avoid
        # a memory leak. If we don't check, the defaultdict backing `self._listeners`
        # will add a new set-object fot every target we try to look up.
        if not target in self._listeners:
            return set()
        return self._listeners[target]

    def _lookup_icmp(self, source_address, identifier, sequence_number):
        target = (socket.IPPROTO_ICMP, source_address, identifier, sequence_number)
        return self._lookup(target)

    def _lookup_tcp(self, destination_address, source_port, destination_port, sequence_number):
        target = (socket.IPPROTO_TCP, destination_address, source_port, destination_port, sequence_number)
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
        elif isinstance(payload, packet.Tcp):
            return self._lookup_tcp(address, payload.source_port, payload.destination_port, payload.sequence_number)
        else:
            return set() # Unknown payload type

    def _find_payload_futures(self, source_address, payload):
        if isinstance(payload, packet.IcmpEchoReply):
            return self._lookup_icmp(source_address, payload.identifier, payload.sequence_number)
        elif isinstance(payload, packet.IcmpTimeExceeded):
            return self._find_inner_payload_futures(payload)
        elif isinstance(payload, packet.IcmpDestinationUnreachable):
            return self._find_inner_payload_futures(payload)
        elif isinstance(payload, packet.Tcp):
            sequence_number = (payload.acknowledgment_number - 1) & 0xffffffff
            return self._lookup_tcp(source_address, payload.destination_port, payload.source_port, sequence_number)
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

    def get_source_address(self, target):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect( (str(target), 0) )
            source_address, source_port = s.getsockname()
            return ipaddress.ip_address(source_address)

    def find_free_icmp_sequence_number(self, target, identifier):
        while True:
            sequence_number = random.randrange(0x10000)
            if self._lookup_icmp(target, identifier, sequence_number):
                # Something else is already using this sequence number
                continue
            return sequence_number

    def find_free_tcp_sequence_number(self, target, source_port, destination_port):
        while True:
            sequence_number = random.randrange(0x100000000)
            if self._lookup_tcp(target, source_port, destination_port, sequence_number):
                # Something else is already using this sequence number
                continue
            return sequence_number

    def send(self, raw_packet):
        destination_address = raw_packet[16:20]
        destination_address = ipaddress.IPv4Address(destination_address)
        destination_address = str(destination_address)
        sock = self._get_transmit_socket(socket.AF_INET)
        sock.sendto(raw_packet, (destination_address, 0))
        sent = time.clock_gettime(time.CLOCK_MONOTONIC)
        return sent
