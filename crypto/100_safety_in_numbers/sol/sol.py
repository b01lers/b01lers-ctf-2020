import os, gmpy2


os.system("openssl rsa -pubin -in pubkey.pem -text | head -n 2")
os.system("openssl rsa -pubin -in pubkey.pem -text | grep Expon")

# => e = 65537
#    n = (10 million + some) bits
#
# => for not to long |m| <= 19 bytes, RSA is trivially invertible via e-th root
#
# try it

e = 65537

def dec(ctxt):
   c = int.from_bytes(ctxt, byteorder = 'little')
   eth_root = gmpy2.iroot(c, e)
   if eth_root[1] != True:
      print("not trivial RSA")
   m = int(eth_root[0])
   msg = (m).to_bytes(m.bit_length() // 8 + 1, byteorder = 'little')
   return msg

with open("flag.enc", "rb") as f:
   ctxt = f.read()

print(dec(ctxt))
