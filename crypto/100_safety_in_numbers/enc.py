import sys
import Crypto.PublicKey.RSA as RSA


def enc(msg, pubkey):
   (n,e) = pubkey
   m = int.from_bytes(msg, byteorder = 'little')
   c = pow(m, e, n)
   ctxt = (c).to_bytes(c.bit_length() // 8 + 1, byteorder = 'little')
   return ctxt


with open("pubkey.pem", "r") as f:
   ciph = RSA.importKey(f.read())     # chill out, Crypto.RSA takes its sweet time... (minutes)

pubkey = (ciph.n, ciph.e)


with open("flag.txt", "rb") as f:
   flag = f.read()

sys.stdout.buffer.write(enc(flag, pubkey))



