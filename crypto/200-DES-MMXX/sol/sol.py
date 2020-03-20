# 2020 repeated DES encryptions with unique/random DES keys, each selected 
# from a set of 4 possibilities
#
# selections are based on bits of SECRET, and are *not* independent
# first 1010 encryptions use lower 20 bits only, next 1010 encryptions
# use upper 20 bits only
# 
# => solve via brute-force search using meet-in-the-middle 
#    (also hinted at in the description)
#
# full keyspace: 2^40 = 2^20 * 2^20
# keyspace with 2 hex digits shown as hint:  2^32 = 2^16 * 2^16
#


import sys
from hashlib import sha256
from Crypto.Cipher import DES

SECRET = 0xa00000000e
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
 
def encrypt(keys, msg, s):
   dk = scramble(s)
   for v in keys:
      idx = dk & 3
      dk >>= 2
      k = v[idx*8:(idx+1)*8]
      cp = DES.new(k, DES.MODE_CBC, bytes(8))  
      msg = cp.encrypt(msg)
   return msg


# inverse of encrypt()
def decrypt(keys, ctxt, s):
   dk = scramble(s)
   for v in keys[::-1]:
      idx = (dk >> 4038) & 3   # FIXME: could be made more efficient, in principle
      dk <<= 2
      k = v[(idx*8):(idx+1)*8]
      cp = DES.new(k, DES.MODE_CBC, bytes(8))  
      ctxt = cp.decrypt(ctxt)
   return ctxt


# DES-MX encryptor for meet in the middle
def encHLF(keys, msg, s):
   dk = scramble(s)
   # use only first half of the keys
   for i in range(len(keys) // 2):
      v = keys[i]
      idx = dk & 3
      dk >>= 2
      k = v[idx*8:(idx+1)*8]
      cp = DES.new(k, DES.MODE_CBC, bytes(8))  
      msg = cp.encrypt(msg)
   return msg


# DES-MX decryptor for meet in the middle
def decHLF(keys, ctxt, s):
   dk = scramble(s)
   # use only second half of the keys
   n = len(keys)
   for i in range(n // 2):
      v = keys[n - i - 1]
      idx = (dk >> 4038) & 3
      dk <<= 2
      k = v[(idx*8):(idx+1)*8]
      cp = DES.new(k, DES.MODE_CBC, bytes(8))  
      ctxt = cp.decrypt(ctxt)
   return ctxt


keys = keygen(seed)

# break SECRET into two 20-bit parts, perform meet in middle
#
msg  = b"Attack at DAWN!!"
ctxt = b"\x15\x08\x54\xff\x3c\xf4\xc4\xc0\xd2\x3b\xd6\x8a\x82\x34\x83\xbe"


# generate DES-MX encryption table for known ptxt, store as hashmap
n=0x10000
c2map = {}
for s in range(n):
   if (s & 0xfff) == 0:           # progress indicator (every 6.25%)
      sys.stderr.write(".")
      sys.stderr.flush()
   s1 = (0xa0000 + s) << 20
   c2map[ encHLF(keys, msg, s1) ] = s1

# match against DES-MX decryption of corresponding ctxt
for s in range(n) :
   s2 = 0x0000e + (s << 4)
   m2 = decHLF(keys, ctxt, s2)
   if c2map.get(m2) != None:      # if match found
      SECRET = c2map[m2] + s2
      print(hex(SECRET))
      break


# decrypt flag with reconstructed SECRET
with open("flag.enc", "rb") as f:
   ctxt = f.read()

print(decrypt(keys, ctxt, SECRET))


# ballpark 15 minutes on a Surface Pro
# (full 2^40 keyspace would have taken a few hours :/)
