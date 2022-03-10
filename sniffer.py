import socket
from function import * 
from components.ipv4 import IPv4
from components.pcap import Pcap
from components.ethernet import Ethernet

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '

DATA_TAB_1 = '\t  '

def main():
   
    # Cria um socket de rede utilizando funções nativas do python
    pcap = Pcap('capture.pcap') 
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    # Loop executado infinitamente para capturar qualquer pacote de entrada
    while True:
        # Escuta na porta 65565
        data = sock.recvfrom(65535)
        pcap.write(data)
        eth = Ethernet(data)

        print('\nEthernet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        #Captura pacote ipv4
        if(eth.proto == 8):
            ipv4 = IPv4(ipv4.data)
            print(TAB_1 + 'Ipv4 Packet:' )
            print(TAB_2 + 'Destination: {}, Source: {}, Protocol: {}'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_3 + 'Protocol: {}, Source{}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
        else:
            print('Ethernet Data: ')
            print(format_multi_line(DATA_TAB_1, eth.data))
    pcap.cloce()
main()