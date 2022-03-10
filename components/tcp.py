import struct

class TCP:

    def __init__(self, data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reversed_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reversed_flags >> 12) * 4
        self.flag_urg = (offset_reversed_flags & 32) >> 5
        self.flag_ack = (offset_reversed_flags & 16) >> 4
        self.flag_psh = (offset_reversed_flags & 8) >> 3
        self.flag_rst = (offset_reversed_flags & 4) >> 2
        self.flag_syn = (offset_reversed_flags & 2) >> 1
        self.flag_fin = offset_reversed_flags & 1
        self.data = data[offset:]