import struct


class ICMP:

    def __init__(self, data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', data[:4])
        self.data = data[4:]
