import sys
from hashlib import sha256
from Crypto.Cipher import DES
from Crypto import Random

SECRET = 0xa4d9e3618e
#SECRET = int.from_bytes(Random.get_random_bytes(5), 'little')
#print(hex(SECRET))
seed = b'secret_sauce_#9'    


def keygen(s):
   keys = []
   for i in range(2020):
      s = sha256(s).digest()
      keys.append(s)
   return keys

def scramble(s):
   ret = "".join( [format(s & 0xfffff, '020b')]*101 )
   ret += "".join( [format(s >> 20, '020b')]*101 )
   return int(ret, 2)
 
def encrypt(keys, msg):
   dk = scramble(SECRET)
   for v in keys:
      idx = dk & 3
      dk >>= 2
      k = v[idx*8:(idx+1)*8]
      cp = DES.new(k, DES.MODE_CBC, bytes(8))  
      msg = cp.encrypt(msg)
   return msg


def decrypt(keys, ctxt):
   dk = scramble(SECRET)
   for v in keys[::-1]:
      idx = (dk >> 4038) & 3
      dk <<= 2
      k = v[(idx*8):(idx+1)*8]
      cp = DES.new(k, DES.MODE_CBC, bytes(8))  
      ctxt = cp.decrypt(ctxt)
   return ctxt


keys = keygen(seed)

with open("flag.txt", "rb") as f:
   msg = f.read()

ctxt = encrypt(keys, msg)
with open("flag.enc", "wb") as f:
   f.write(ctxt)
#sys.stdout.buffer.write(ctxt)

msg2 = decrypt(keys, ctxt)
print(msg2)
