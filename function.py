import textwrap

def get_mac_addr(mac):
    byte = map('{:02}'.format, mac)
    destination_mac = ':'.join(byte).upper()
    return destination_mac

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])    
    