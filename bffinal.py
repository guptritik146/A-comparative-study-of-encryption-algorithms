import blowfish

cipher = blowfish.Cipher(b"Key must be between 4 and 56 bytes long.")

from operator import xor
from os import urandom





# increment by one counters
nonce = int.from_bytes(urandom(8), "big")
enc_counter = blowfish.ctr_counter(nonce, f = xor)
dec_counter = blowfish.ctr_counter(nonce, f = xor)



