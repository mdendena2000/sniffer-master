from email.base64mime import header_length
import struct

class IPv4:

    def __init__(self, data):
        version_header_length = data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s', data[:20])
        self.src = self.ipv4(src, target)
        self.target = self.ipv4(target)
        self.data = data[self.header_length]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))
        