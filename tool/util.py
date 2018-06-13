
def decode_hex(x):
    length = len(x)
    if length % 2 == 1:
        x = "0" + x
    assert length % 2 == 0
    b = []
    for i in range(0,length,2):
        b.append(chr(int(x[i:i+2], base=16)))
    return ''.join(b).encode("utf-8")

def encode_hex(b):
    """
    Take a string of raw bytes and return a hexidecimal representation.
    """
    raw = []
    if type(b) is str:
        raw = [ord(x) for x in list(b)]
    elif type(b) is bytes:
        raw = list(b)
        
    return ''.join(['{:02x}'.format(x) for x in raw])
