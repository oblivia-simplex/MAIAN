import eth_hash.backends.pycryptodome as k
import eth_utils
from web3 import Web3

class keccak_256():

    def __init__(self):
        self._buf = b''

    def update(self, b:bytes):
        self._buf += b

    def hexdigest(self):
        h = k.keccak256(self._buf)
        h = eth_utils.encode_hex(h)
        return h[2:]


def chksum_fmt(addr):
    return Web3.toChecksumAddress(addr)
