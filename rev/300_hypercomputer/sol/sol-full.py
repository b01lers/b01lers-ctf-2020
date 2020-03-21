#
# equivalent python v2 code, for those that completely reversed the challenge
#
# [at its heart, the binary had simple math routines (add, sub, cmp, div 2, mod 2, etc), implemented on a 1D Turing machine]
#

import sys
from pwn import *

# connect to challenge, read freq/mem from line 4 of output

r = remote("localhost", 13370)

in1 = r.recvuntil("kZB")
print(in1)

freq = float(in1.split()[-6])
mem = float(in1.split()[-2])

print("freq,mem=", freq, mem)


# compute integer freqi, memi

freqi = (14. - freq) / 5. * 65535
memi = (64. - mem) / 50. * 65535

freqi = int(freqi + 0.5)  # round
memi = int(memi + 0.5)

print("freqi,memi=", freqi, memi)


# compute coordinates

def fsum(a, b):
   vals = []
   for i in range(16):
      if (b & 1) == 0:
         vals.append(a)
      else:
         vals.append(b)
      b //= 2
   return sum(vals)


def gmod(a, b):
   ra = a % 2020
   rb = b % 2020
   if (ra + rb > 1000):
      return a // 2 + b
   else:
      return b // 2 + a



x = fsum(freqi, memi)
y = gmod(freqi, memi)


print("x,y=", x,y)
sys.stdout.flush()


# send answer

print(r.recvuntil("coordinates:"))

r.send(str(x) + "," + str(y) + "\n")

print(r.recvall())

