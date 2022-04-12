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

DATA_TAB_1 = '\t   '

# verde = '\033[32m'
# restaura cor original = '\033[0;0m'

def main():

    pcap = Pcap('capture.pcap')
    # Cria um socket de rede utilizando funções nativas do python
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
    # Escuta na porta 65565 // 65535
    data, addr = sock.recvfrom(65535)
    pcap.write(data)
    eth = Ethernet(data)

    print('\033[32m' + '\nEthernet Frame:' + '\033[0;0m')
    print(TAB_1 + 'Destination: {}'.format(eth.dest_mac))
    print(TAB_1 + 'Source: {}'.format(eth.src_mac))
    print(TAB_1 + 'Protocol: {}'.format(eth.proto))   

    #while True:
    #IPv4
    if (eth.proto == 8):
        ipv4 = IPv4(eth.data)
        print('\033[32m' + '\nIPV4:' + '\033[0;0m')
        print(TAB_1 + 'Version: {}'.format(ipv4.version))
        print(TAB_1 + 'Header Length: {}'.format(ipv4.header_length))
        print(TAB_1 + 'TTL: {}'.format(ipv4.ttl))
        print(TAB_1 + 'Protocol: {}'.format(ipv4.proto))
        print(TAB_1 + 'Source: {}'.format(ipv4.src))
        print(TAB_1 + 'Target: {}'.format(ipv4.target))

        # ICMP
        if (ipv4.proto == 1):
            icmp = ICMP(ipv4.data)
            print('\033[32m' + '\nICMP:' + '\033[0;0m')
            print(TAB_1 + 'Type: {}'.format(icmp.type))
            print(TAB_1 + 'Code: {}'.format(icmp.code))
            print(TAB_1 + 'Checksum: {}'.format(icmp.checksum))

            print('\nICMP Data:')
            print(format_multi_line(DATA_TAB_1, icmp.data))

        # TCP
        elif (ipv4.proto == 6):
            tcp = TCP(ipv4.data)
            print('\033[32m' + '\nTCP:' + '\033[0;0m')
            print(TAB_1 + 'Source Port: {}'.format(tcp.src_port))
            print(TAB_1 + 'Destination Port: {}'.format(tcp.dest_port))
            print(TAB_1 + 'Sequence: {}'.format(tcp.sequence))
            print(TAB_1 + 'Acknowledgment: {}'.format(tcp.acknowledgment))

            print('\033[32m' + '\n' + DATA_TAB_1 + 'Flags:' + '\033[0;0m')
            print(TAB_2 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
            print(TAB_2 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

            if len(tcp.data) > 0:
                # HTTP
                if (tcp.src_port == 80 or tcp.dest_port) == 80:
                    print('\033[32m' + '\nHTTP Data:' + '\033[0;0m')
                    try:
                        http = HTTP(tcp.data)
                        http_info = str(http.data).split('\n')
                                
                        for line in http_info:
                            print(DATA_TAB_1 + str(line))
                    except:
                        print(format_multi_line(DATA_TAB_1, tcp.data))
                
                else:
                    print('\033[32m' + '\nTCP Data:' + '\033[0;0m')
                    print(format_multi_line(DATA_TAB_1, tcp.data))

        # UDP
        elif (ipv4.proto == 17):
            udp = UDP(ipv4.data)
            print('\033[32m' + '\nUDP:' + '\033[0;0m')
            print(TAB_1 + 'Source Port: {}'.format(udp.src_port))
            print(TAB_1 + 'Destination Port: {}'.format(udp.dest_port))
            print(TAB_1 + 'Length: {}'.format(udp.size))
        
        # Outros IPv4
        else:
            print('\033[32m' + '\nOutros IPV4 Data:' + '\033[0;0m')
            print(format_multi_line(DATA_TAB_1, ipv4.data))

    # Captura pacotes IPv6
    elif (eth.proto == 56710):
        ipv6 = IPv6(eth.data)
        print('\033[32m' + '\nIPV6:' + '\033[0;0m')
        print(TAB_1 + 'Version: {}'.format(ipv6.version))
        print(TAB_1 + 'Traffic Class: {}'.format(ipv6.traffic_class))
        print(TAB_1 + 'Flow Label: {}'.format(ipv6.flow_label))

        print(TAB_1 + 'Payload Length: {}'.format(ipv6.payload_length))
        print(TAB_1 + 'Next Header: {}'.format(ipv6.next_header))
        print(TAB_1 + 'Hop Limit: {}'.format(ipv6.hop_limit))

        print(TAB_1 + 'Source Address: {}'.format(ipv6.source_address))
        print(TAB_1 + 'Destination Address: {}'.format(ipv6.destination_address))
                    
    else:
        print('\033[32m' + '\nEthernet Data:' + '\033[0;0m')
        print(format_multi_line(DATA_TAB_1, eth.data))        

    pcap.close()   

main()