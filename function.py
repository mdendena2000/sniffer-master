import textwrap

def get_mac_addr(mac):
    byte = map('{:02}'.format, mac)
    destination_mac = ':'.join(byte).upper()
    return destination_mac