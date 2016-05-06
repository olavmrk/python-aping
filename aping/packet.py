import collections
import ipaddress
import struct

ipv4_any = ipaddress.IPv4Address('0.0.0.0')

def _calculate_checksum(data):
    if len(data) % 2 == 1: # Odd number of bytes
        data += b'\0'
    checksum = 0
    for pos in range(0, len(data), 2):
        b1 = data[pos]
        b2 = data[pos + 1]
        checksum += (b1 << 8) + b2
    checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = ~checksum & 0xffff
    return checksum


class _StructHelper(object):

    def __init__(self, **kwargs):
        valid_fields = { field for field, default_value in self.INIT_FIELDS }
        for key in kwargs.keys():
            if not key in valid_fields:
                raise TypeError('Unknown field: {field}'.format(field=key))

        for field, default_value in self.INIT_FIELDS:
            value = kwargs.get(field, default_value)
            setattr(self, field, value)

    @classmethod
    def from_bytes(cls, data, allow_partial=False):
        ret = cls()
        offset = 0
        for field, fmt in cls.STRUCT_FIELDS:
            if fmt == '*s':
                value = data[offset:]
            else:
                fmt = '>' + fmt
                field_size = struct.calcsize(fmt)
                field_end = offset + field_size
                if field_end > len(data):
                    if not allow_partial:
                        raise ValueError('End of packet when loading {field} field'.format(field=field))
                    value = None
                else:
                    value = struct.unpack(fmt, data[offset:field_end])[0]
                offset = field_end
            setattr(ret, field, value)
        return ret

    def __bytes__(self):
        last_field, last_fmt = self.STRUCT_FIELDS[-1]
        if last_fmt == '*s':
            fields = self.STRUCT_FIELDS[:-1]
            append = getattr(self, last_field)
        else:
            fields = self.STRUCT_FIELDS
            append = b''
        values = [ getattr(self, field) for field, fmt in fields ]
        format_string = '>' + ''.join([ fmt for field, fmt in fields ])
        return struct.pack(format_string, *values) + append

    def __repr__(self):
        init_params = []
        for field, default_value in self.INIT_FIELDS:
            value = getattr(self, field)
            if value != default_value:
                init_params.append('{field}={value}'.format(field=field, value=repr(value)))
        init_params = ', '.join(init_params)
        return '{cls}({params})'.format(cls=type(self).__name__, params=init_params)


class IPv4(_StructHelper):
    STRUCT_FIELDS = (
        ('_struct_version_ihl', 'B'),
        ('_struct_dscp_ecn', 'B'),
        ('total_length', 'H'),
        ('identification', 'H'),
        ('_struct_flags_fragment_offset', 'H'),
        ('time_to_live', 'B'),
        ('protocol', 'B'),
        ('header_checksum', 'H'),
        ('_struct_source_address', '4s'),
        ('_struct_destination_address', '4s'),
    )

    INIT_FIELDS = (
        ('version', 4),
        ('ihl', 5),
        ('dscp', 0),
        ('ecn', 0),
        ('total_length', 0),
        ('identification', 0),
        ('flags', 0),
        ('fragment_offset', 0),
        ('time_to_live', 64),
        ('protocol', 0),
        ('header_checksum', 0),
        ('source_address', ipv4_any),
        ('destination_address', ipv4_any),
        ('options', b''),
        ('payload', b''),
    )

    @property
    def _struct_version_ihl(self):
        return (self.version << 4) | self.ihl
    @_struct_version_ihl.setter
    def _struct_version_ihl(self, value):
        if value is not None:
            self.version = (value & 0b11110000) >> 4
            self.ihl = value & 0b1111
        else:
            self.version = None
            self.ihl = None

    @property
    def _struct_dscp_ecn(self):
        return (self.dscp << 2) | self.ecn
    @_struct_dscp_ecn.setter
    def _struct_dscp_ecn(self, value):
        if value is not None:
            self.dscp = (value & 0b11111100) >> 2
            self.ecn = value & 0b00000011
        else:
            self.dscp = None
            self.ecn = None

    @property
    def _struct_flags_fragment_offset(self):
        return (self.flags << 13) | self.fragment_offset
    @_struct_flags_fragment_offset.setter
    def _struct_flags_fragment_offset(self, value):
        if value is not None:
            self.flags = (value & 0b1110000000000000) >> 2
            self.fragment_offset = value & 0b0001111111111111
        else:
            self.flags = None
            self.fragment_offset = None

    @property
    def _struct_source_address(self):
        return self.source_address.packed
    @_struct_source_address.setter
    def _struct_source_address(self, value):
        if value is not None:
            self.source_address = ipaddress.IPv4Address(value)
        else:
            self.source_address = None

    @property
    def _struct_destination_address(self):
        return self.destination_address.packed
    @_struct_destination_address.setter
    def _struct_destination_address(self, value):
        if value is not None:
            self.destination_address = ipaddress.IPv4Address(value)
        else:
            self.destination_address = None

    def calculate_checksum(self):
        self.checksum = 0
        data = self._header_bytes()
        self.checksum = _calculate_checksum(data)

    def embed_payload(self, payload):
        if not hasattr(payload, 'ipv4_protocol'):
            raise ValueError('Unsupported payload type: {type}'.format(type=type(payload).__name__))
        self.protocol = payload.ipv4_protocol
        self.payload = bytes(payload)
        self.total_length = 20 + len(self.options) + len(self.payload)
        self.calculate_checksum()

    def extract_payload(self, allow_partial=False):
        protocols = {
            1: Icmp,
            6: Tcp,
        }
        protocol_type = protocols.get(self.protocol, None)
        if protocol_type is None:
            raise NotImplementedError('Unsupported protocol: {protocol}'.format(protocol=self.protocol))
        return protocol_type.from_ipv4(self, allow_partial=allow_partial)

    @classmethod
    def from_bytes(cls, data, allow_partial=False):
        ret = super().from_bytes(data, allow_partial)
        ret.options = None
        ret.payload = None
        if ret.ihl is None:
            return ret # An empty packet
        if ret.ihl < 5:
            raise ValueError('ihl field in IPv4 packet must be at least 5; was {ihl}'.format(ihl=ret.ihl))
        options_end = ret.ihl * 4
        if options_end >= len(data):
            return ret # Packet ended before options were completed
        ret.options = data[20:options_end]
        ret.payload = data[options_end:]
        return ret

    def _header_bytes(self):
        header = super().__bytes__()
        return header + self.options

    def __bytes__(self):
        return self._header_bytes() + self.payload

class Icmp(_StructHelper):
    STRUCT_FIELDS = (
        ('type', 'B'),
        ('code', 'B'),
        ('checksum', 'H'),
    )
    INIT_FIELDS = (
        ('type', 0),
        ('code', 0),
        ('checksum', 0),
    )

    ipv4_protocol = 1

    @staticmethod
    def _init_fields(icmp_type):
        return (
            ('type', icmp_type),
            ('code', 0),
            ('checksum', 0),
        )

    def calculate_checksum(self):
        self.checksum = 0
        data = bytes(self)
        self.checksum = _calculate_checksum(data)

    @classmethod
    def from_ipv4(cls, ipv4_packet, allow_partial=False):
        data = ipv4_packet.payload
        if data is None or len(data) < 1:
            return IcmpUnknown.from_bytes(b'', allow_partial)
        icmp_type = data[0]
        type_map = {
            0: IcmpEchoReply,
            3: IcmpDestinationUnreachable,
            8: IcmpEchoRequest,
            11: IcmpTimeExceeded,
        }
        icmp_type = type_map.get(icmp_type, IcmpUnknown)
        return icmp_type.from_bytes(data, allow_partial)

class IcmpUnknown(Icmp):
    STRUCT_FIELDS = Icmp.STRUCT_FIELDS + (
        ('data', '*s'),
    )
    INIT_FIELDS = Icmp._init_fields(0) + (
        ('data', b''),
    )

class IcmpEchoReply(Icmp):
    STRUCT_FIELDS = Icmp.STRUCT_FIELDS + (
        ('identifier', 'H'),
        ('sequence_number', 'H'),
        ('payload', '*s'),
    )
    INIT_FIELDS = Icmp._init_fields(0) + (
        ('identifier', 0),
        ('sequence_number', 0),
        ('payload', b''),
    )

class IcmpDestinationUnreachable(Icmp):
    STRUCT_FIELDS = Icmp.STRUCT_FIELDS + (
        ('unused', 'H'),
        ('next_hop_mtu', 'H'),
        ('payload', '*s'),
    )
    INIT_FIELDS = Icmp._init_fields(3) + (
        ('unused', 0),
        ('next_hop_mtu', 0),
        ('payload', b''),
    )

    def extract_payload(self):
        return IPv4.from_bytes(self.payload, allow_partial=True)

class IcmpEchoRequest(Icmp):
    STRUCT_FIELDS = Icmp.STRUCT_FIELDS + (
        ('identifier', 'H'),
        ('sequence_number', 'H'),
        ('payload', '*s'),
    )
    INIT_FIELDS = Icmp._init_fields(8) + (
        ('identifier', 0),
        ('sequence_number', 0),
        ('payload', b''),
    )

class IcmpTimeExceeded(Icmp):
    STRUCT_FIELDS = Icmp.STRUCT_FIELDS + (
        ('unused', 'I'),
        ('payload', '*s'),
    )
    INIT_FIELDS = Icmp._init_fields(11) + (
        ('unused', 0),
        ('payload', b''),
    )

    def extract_payload(self):
        return IPv4.from_bytes(self.payload, allow_partial=True)

class Tcp(_StructHelper):
    STRUCT_FIELDS = (
        ('source_port', 'H'),
        ('destination_port', 'H'),
        ('sequence_number', 'I'),
        ('acknowledgment_number', 'I'),
        ('_struct_misc', 'B'),
        ('_struct_flags', 'B'),
        ('window_size', 'H'),
        ('checksum', 'H'),
        ('urgent_pointer', 'H'),
    )
    INIT_FIELDS = (
        ('source_port', 0),
        ('destination_port', 0),
        ('sequence_number', 0),
        ('acknowledgment_number', 0),
        ('data_offset', 5),
        ('reserved', 0),
        ('ns', False),
        ('cwr', False),
        ('ece', False),
        ('urg', False),
        ('ack', False),
        ('psh', False),
        ('rst', False),
        ('syn', False),
        ('fin', False),
        ('window_size', 0),
        ('checksum', 0),
        ('urgent_pointer', 0),
        ('options', b''),
        ('data', b''),
    )

    ipv4_protocol = 6

    @property
    def _struct_misc(self):
        ret = (self.data_offset << 4) | (self.reserved << 1)
        if self.ns:
            ret |= 0b1
        return ret
    @_struct_misc.setter
    def _struct_misc(self, value):
        if value is not None:
            self.data_offset = (value & 0b11110000) >> 4
            self.reserved = (value & 0b1110) >> 1
            self.ns = bool(value & 0b1)
        else:
            self.data_offset = None
            self.reserved = None
            self.ns = None

    @property
    def _struct_flags(self):
        ret = 0
        if self.cwr:
            ret |= 0b10000000
        if self.ece:
            ret |= 0b01000000
        if self.urg:
            ret |= 0b00100000
        if self.ack:
            ret |= 0b00010000
        if self.psh:
            ret |= 0b00001000
        if self.rst:
            ret |= 0b00000100
        if self.syn:
            ret |= 0b00000010
        if self.fin:
            ret |= 0b00000001
        return ret
    @_struct_misc.setter
    def _struct_flags(self, value):
        if value is not None:
            self.cwr = bool(value & 0b10000000)
            self.ece = bool(value & 0b01000000)
            self.urg = bool(value & 0b00100000)
            self.ack = bool(value & 0b00010000)
            self.psh = bool(value & 0b00001000)
            self.rst = bool(value & 0b00000100)
            self.syn = bool(value & 0b00000010)
            self.fin = bool(value & 0b00000001)
        else:
            self.cwr = None
            self.ece = None
            self.urg = None
            self.ack = None
            self.psh = None
            self.rst = None
            self.syn = None
            self.fin = None

    @classmethod
    def from_bytes(cls, data, allow_partial=False):
        ret = super().from_bytes(data, allow_partial)
        ret.options = None
        ret.data = None
        if ret.data_offset is None:
            return ret # We don't have any options or data
        if ret.data_offset < 5:
            raise ValueError('data_offset field in TCP header must be at least 5; was {data_offset}'.format(data_offset=ret.data_offset))
        options_end = ret.data_offset * 4
        if options_end >= len(data):
            return ret # Packet ended before options were completed
        ret.options = data[20:options_end]
        ret.data = data[options_end:]
        return ret

    def __bytes__(self):
        header = super().__bytes__()
        return header + self.options + self.data

    def calculate_checksum(self, source_address, destination_address):
        self.checksum = 0
        data = bytes(self)
        pseudo_header = source_address.packed + destination_address.packed + struct.pack('>BBH', 0, 6, len(data))
        self.checksum = _calculate_checksum(pseudo_header + data)

    @classmethod
    def from_ipv4(cls, ipv4_packet, allow_partial=False):
        data = ipv4_packet.payload
        if data is None:
            data = ''
        return Tcp.from_bytes(data, allow_partial)

