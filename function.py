import textwrap
import struct


# Retorna endereço MAC
def get_mac_addr(mac):
    byte_str = map('{:02x}'.format, mac)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

# Formata linhas
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Formata IPV6
def get_ipv6_address(raw_data):
    address = ":".join(map('{:04x}'.format, struct.unpack('! H H H H H H H H', raw_data)))
    return address.replace(":0000:","::" ).replace(":::", "::").replace(":::", "::")