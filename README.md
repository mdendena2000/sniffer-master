## Sniffer-master

Este trabalho visa implementar um de software livre. O trabalho é um pré-requisito para empacotar pacotes de rede. O objetivo deste trabalho é contribuir com desenvolvimento de software e a comunidade de software livre, para praticar os conceitos da disciplina.

### Para que serve um sniffer de pacotes

Qualquer rede convencional transporta dados em pacotes que são fabricados por um servidor (ou computador) e enviados para um ou mais servidores na mesma rede. Por motivos de segurança, pode-se querer analisar o tráfego que essa rede produz. Isso significa acompanhar os pacotes que trafegam pela rede "farejando" ou detectando-os e decodificando seu conteúdo.

### Recursos da ferramenta

- Endereço MAC (Destino e Origem)
- Protocolo Ethernet
- Protocolo TCP
- Identificação e tratamento para protocolo ICMP;
- Identificação e tratamento para protocolo UDP;
- Ipv4 / IPv6 / HTTP;

### Para executar:

su python3 sniffer.py


