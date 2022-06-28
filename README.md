## Sniffer

### Para que serve um Analisador de Pacotes

Redes convencionais transportam dados em pacotes que são fabricados por um servidor (ou computador) e enviados para um ou mais servidores na mesma rede. Por motivos de segurança, pode-se querer analisar o tráfego que essa rede produz. Isso significa acompanhar os pacotes que trafegam pela rede "farejando" ou detectando-os e decodificando seu conteúdo.

Para realização desse programa foi utilizado [API Python Socket](https://docs.python.org/3/library/socket.html).

### Recursos

- Endereço MAC (Destino e Origem);
- Protocolo Ethernet;
- Protocolo IPv4;
- Protocolo TCP;
- Protocolo ICMP;
- Protocolo UDP;
- Protocolo IPv6.

### Execução:
```bash
sudo su python3 sniffer.py
```
