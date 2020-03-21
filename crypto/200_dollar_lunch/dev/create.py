# creates normal RSA or challenge problem
# in human-readable form
#
# usage:  python3 create.py [RSA|not RSA]
#


import sys, os, gmpy2, Crypto.Random.random


e = 65537


# prime generation

def countBits(v):     # replaceable with int.bit_length() but what the heck :)
   cnt = 0
   while v > 0:
      cnt += 1
      v //= 2
   return cnt

def gen_prime(bits):
   while True:
      p = Crypto.Random.random.getrandbits(bits)
      if countBits(p) != bits:     # make sure bit count is exactly right
         continue
      if gmpy2.is_prime(p):
         return p

# p & q generation 

def gcd(x, y) :
   while x != 0 :
      x,y = y % x, x
   return y

def gen_pq_RSA(bits):
   while True:
      p = gen_prime(bits)
      q = gen_prime(bits)
      N = p * q
      phi = (p-1) * (q-1)     # correct
      if gcd(phi, e) == 1:
         return (N, p, q, phi)

def gen_pq_CHALL(bits, bits2):
   while True:
      p = gen_prime(bits)
      q1  = gen_prime(bits - 2 * bits2)
      q2  = gen_prime(bits2)
      q = q1 * q2 * q2
      if countBits(q) != bits:
         continue
      N = p * q
      phi = (p-1) * (q-1)   # naive
      if gcd(phi, e) == 1:
         print("q1=%d" % q1)
         print("q2=%d" % q2)
         return (N, p, q, phi)

# encrypt method (std RSA)

def encrypt(m):
   return pow(m, e, N)



# read params, generate N,p,q,phi

(N, p, q, phi) = gen_pq_RSA(1024)   if   sys.argv[1] == "RSA"   else  gen_pq_CHALL(1024, 80)


print("N=%d" % N)
print("p=%d" % p)
print("q=%d" % q)
print("%d %d %d" % (countBits(N), countBits(p), countBits(q)) )
print("phi_naive=%d" % phi)
print("e=%d" % e)


# create encrypted chunks
# the file info.html has the flag in a comment

def encrypt(m):
   return pow(m, e, N)

with open("info.html", "rb") as f:
   data = f.read()

chunkSize = 250   # slightly smaller than length of N (ensures m < N)
Nchunks = (len(data) // chunkSize) + 1
chunks = [data[i*chunkSize:(i+1)*chunkSize] for i in range(Nchunks)]

for i,msg in enumerate(chunks):
   m = int.from_bytes(msg, byteorder='big', signed=False)
   c = encrypt(m)
   fname = "secret" + ("000" + str(i))[-4:]
   with open(fname, "wb") as f:
       f.write(c.to_bytes(256, byteorder = 'big'))


# create tarball
os.system("tar czf capture.tar.gz secret*")
os.system("rm -f secret[0-9]*")
