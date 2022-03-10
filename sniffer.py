import socket
from function import * 
from components.ipv4 import IPv4
from components.pcap import Pcap
from components.ethernet import Ethernet
from components.http import HTPP
from components.tcp import TCP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '

DATA_TAB_1 = '\t  '
DATA_TAB_2 = '\t\t  '
DATA_TAB_3 = '\t\t\t  '

def main():
   
    # Cria um socket de rede utilizando funções nativas do python
    pcap = Pcap('capture.pcap') 
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    # Loop executado infinitamente para capturar qualquer pacote de entrada
    while True:
        # Escuta na porta 65535
        data = sock.recvfrom(65535)
        pcap.write(data)
        eth = Ethernet(data)

        print('\nEthernet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        #Ipv4
        if(eth.proto == 8):
            ipv4 = IPv4(ipv4.data)
            print(TAB_1 + 'Ipv4 Packet:' )
            print(TAB_2 + 'Destination: {}, Source: {}, Protocol: {}'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_3 + 'Protocol: {}, Source{}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            #TCP
            if (ipv4.proto == 6):
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'. format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN: {}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    #HTPP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTPP Data: ')
                        try:
                            http = HTPP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3. tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data: ')
                        print(format_multi_line(DATA_TAB_3, tcp.data))
                else:
                    print(TAB_1 + 'Outros Ipv4 Data: ')
                    print(format_multi_line(DATA_TAB_1, eth.data))
        else:
            print('Ethernet Data: ')
            print(format_multi_line(DATA_TAB_1, eth.data))

    pcap.close()
main()