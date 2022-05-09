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

    pcap = Pcap('capturas.pcap')
    # Cria um socket de rede
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # Converte inteiros positivos de 16 bits da rede para a ordem de bytes do host.

    # Escuta na porta 65535 // 65536
    data, addr = sock.recvfrom(65536)
    pcap.write(data)

    # Ethernet
    eth = Ethernet(data)
    print('\033[32m' + '\nEthernet Frame:' + '\033[0;0m')
    print(TAB_1 + 'Endereço MAC destino: {}'.format(eth.dest_mac))
    print(TAB_1 + 'Endereço MAC origem: {}'.format(eth.src_mac))
    print(TAB_1 + 'Protocolo: {}'.format(eth.proto))

    # A variavel (proto) está se referindo ao tipo de frame se for 8 vem o pacote IPv4.
    # A variavel (proto) está se referindo ao tipo de frame se for 56710 vem o pacote IPv6.   

    #IPv4
    if (eth.proto == 8):
        ipv4 = IPv4(eth.data)
        print('\033[32m' + '\nIPV4:' + '\033[0;0m')
        print(TAB_1 + 'Versão: {}'.format(ipv4.version))
        print(TAB_1 + 'Comprimento do Cabeçalho: {}'.format(ipv4.header_length))
        print(TAB_1 + 'TTL: {}'.format(ipv4.ttl))
        print(TAB_1 + 'Protocolo: {}'.format(ipv4.proto))
        print(TAB_1 + 'Endereço Origem: {}'.format(ipv4.src))
        print(TAB_1 + 'Endereço Destino: {}'.format(ipv4.target))

        # ICMP
        if (ipv4.proto == 1):
            icmp = ICMP(ipv4.data)
            print('\033[32m' + '\nICMP:' + '\033[0;0m')
            print(TAB_1 + 'Tipo: {}'.format(icmp.type))
            print(TAB_1 + 'Código: {}'.format(icmp.code))
            print(TAB_1 + 'Checksum: {}'.format(icmp.checksum))

            print('\nICMP Data:')
            print(format_multi_line(DATA_TAB_1, icmp.data))

        # TCP
        elif (ipv4.proto == 6):
            tcp = TCP(ipv4.data)
            print('\033[32m' + '\nTCP:' + '\033[0;0m')
            print(TAB_1 + 'Porta Origem: {}'.format(tcp.src_port))
            print(TAB_1 + 'Porta Destino: {}'.format(tcp.dest_port))
            print(TAB_1 + 'Sequencia: {}'.format(tcp.sequence))
            print(TAB_1 + 'Reconhecimento: {}'.format(tcp.acknowledgment))

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
            print(TAB_1 + 'Porta Origem: {}'.format(udp.src_port))
            print(TAB_1 + 'Porta Destino: {}'.format(udp.dest_port))
            print(TAB_1 + 'Comprimento: {}'.format(udp.size))
        
        # Outros IPv4
        else:
            print('\033[32m' + '\nOutros IPV4 Data:' + '\033[0;0m')
            print(format_multi_line(DATA_TAB_1, ipv4.data))

    # IPv6
    elif (eth.proto == 56710):
        ipv6 = IPv6(eth.data)
        print('\033[32m' + '\nIPV6:' + '\033[0;0m')
        print(TAB_1 + 'Versão: {}'.format(ipv6.version))
        print(TAB_1 + 'Classe de Tráfego: {}'.format(ipv6.traffic_class))
        print(TAB_1 + 'Rótulo de Fluxo: {}'.format(ipv6.flow_label))

        print(TAB_1 + 'Comprimento de Carga: {}'.format(ipv6.payload_length))
        print(TAB_1 + 'Próximo Cabeçalho: {}'.format(ipv6.next_header))
        print(TAB_1 + 'Limite de Saltos: {}'.format(ipv6.hop_limit))

        print(TAB_1 + 'Endereço Origem: {}'.format(ipv6.source_address))
        print(TAB_1 + 'Endereço Destino: {}'.format(ipv6.destination_address))
                    
    else:
        print('\033[32m' + '\nEthernet Data:' + '\033[0;0m')
        print(format_multi_line(DATA_TAB_1, eth.data))        

    pcap.close()
    # fecha arquivo   

main()