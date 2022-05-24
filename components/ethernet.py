import socket
import struct
from function import *

class Ethernet:

    def __init__(self, data):

        dest, src, prototype = struct.unpack('! 6s 6s H', data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = data[14:]
