import socket
from function import *
from components.ethernet import Ethernet
from components.ipv4 import IPv4
from components.ipv6 import IPv6
from components.icmp import ICMP
from components.tcp import TCP
from components.udp import UDP
from components.pcap import Pcap
from components.http import HTTP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():

        pcap = Pcap('capture.pcap')
        # Cria um socket de rede utilizando funções nativas do python
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        # Escuta na porta 65565
        data, addr = sock.recvfrom(65535)
        pcap.write(data)
        eth = Ethernet(data)

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

    #while True:
        # IPv4
        if (eth.proto == 8):
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPV4:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if (ipv4.proto == 1):
                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif (ipv4.proto == 6):
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if (tcp.src_port == 80 or tcp.dest_port) == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif (ipv4.proto == 17):
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Outros IPv4
            else:
                print(TAB_1 + 'Outros IPV4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        # IPv6
        elif (eth.proto == 56710):
            ipv6 = IPv6(eth.data)
            print(TAB_1 + 'IPV6:')
            print(TAB_2 + 'Version: {}, Traffic Class: {}, Flow Label: {},'.format(ipv6.version, ipv6.traffic_class, ipv6.flow_label))
            print(TAB_2 + 'Payload Length: {}, Next Header: {}, Hop Limit: {}'.format(ipv6.payload_length, ipv6.next_header, ipv6.hop_limit))
            print(TAB_2 + 'Source Address: {}, Destination Address: {}'.format(ipv6.source_address, ipv6.destination_address))
            
        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))
            
        #fecha arquivo       
        pcap.close()
    
main()