## Sniffer

### Para que serve um Analisador de Pacotes

Qualquer rede convencional transporta dados em pacotes que são fabricados por um servidor (ou computador) e enviados para um ou mais servidores na mesma rede. Por motivos de segurança, pode-se querer analisar o tráfego que essa rede produz. Isso significa acompanhar os pacotes que trafegam pela rede "farejando" ou detectando-os e decodificando seu conteúdo.

### Recursos da ferramenta

Captura de pacotes IPv4 e IPv6

- Endereço MAC (Destino e Origem);
- Protocolo Ethernet;
- Protocolo TCP;
- Identificação e tratamento para protocolo ICMP;
- Identificação e tratamento para protocolo UDP.

### Para executar:

sudo su python3 sniffer.py
