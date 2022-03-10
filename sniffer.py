import socket
import sys
from components.ipv4 import IPv4

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '

def main():

    try: 
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error:
        print('Socket não criado.')
        sys.exit(1)

    while True:
        data, addr = socket.recfrom(65535)

        ipv4 = IPv4(ipv4.data)
        print(TAB_1 + 'Ipv4 Packet:' )
        print(TAB_2 + 'Destination: {}, Source: {}, Protocol: {}'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
        print(TAB_3 + 'Protocol: {}, Source{}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

        

