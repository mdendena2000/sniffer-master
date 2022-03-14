import struct
from function import *

class IPv6:

    # Captura pacotes IPv6
    def __init__(self, data):
        self.version = data[0] >> 4
        self.traffic_class = ((data[0] & 15) << 4) + (data[1] >> 4)
        self.flow_label = ((data[1] & 15) << 8) + data[2]
        self.flow_label = (self.flow_label << 8) + data[3]
        self.payload_length, self.next_header, self.hop_limit = struct.unpack('! H B B', data[4:8])
        self.source_address = get_ipv6_address(data[8:24])
        self.destination_address = get_ipv6_address(data[24:40])

    def ipv6(self, addr):
        return '.'.join(map(str, addr))
    
