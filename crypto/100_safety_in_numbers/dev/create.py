
import sys, gmpy2, os
import Crypto.Random.random, Crypto.PublicKey.RSA as RSA

e = 65537


# prime generation

def gen_prime(bits):
   p = Crypto.Random.random.getrandbits(bits)
   p |= 1  # make sure it is odd
   while True:
      if gmpy2.is_prime(p):
         break
      sys.stdout.flush()
      p += 2
   return p


# it is super slow to generate O(million)-bit primes, so we cheat
# and generate a massive product of O(thousand)-bit primes 

def genN(bitgoal, bits):   
   N = 1
   i = 0
   while (N).bit_length() < bitgoal:
      p = gen_prime(bits)
      N *= p
      i += 1
      if i % 100 == 0:        # progress indicator, takes about 100 dots.. (go brew some coffee)
         sys.stdout.write(".")
   return N


bitgoal = 10000000
N = genN(bitgoal, 1024)

#print("N=%d" % N)


# store (N,e) in PEM format

ciph = RSA.construct((N, e))
with open("pubkey.pem", "w") as f:
   f.buffer.write(ciph.exportKey('PEM'))


# encrypt flag

os.system("python3 enc.py > flag.enc")
