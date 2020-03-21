import sys

flag = b"pctf{one man's trash is another man's V#x0GFu_Lp%3}\x00"

print("#", len(flag))

base = pow(2, 64)
mask = base - 1

def f(a, b):
   return pow(a, b, base)


a = 113
b = 3
ret = bytearray()
for p in flag:
   x = f(a, b)
   y, z = 0, x
   for i in range(8):
      y ^= z & 0xff
      z >>= 8 
   #print(x, y)
   ret.append(p ^ y)
   b = a
   a = x


with open("pad.bin", "wb") as f:   # for hexdump, in case we spot any structure
   f.write(ret)

for b in ret:                      # for cut-and-paste to C code
   sys.stdout.write(str(int(b)) + ", ")
