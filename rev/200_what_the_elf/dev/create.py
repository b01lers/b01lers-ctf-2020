# save an ELF with tweaked .dynstr and .dynsym tables
# hackish but works for this particular purpose
#
# external .dynstr symbols start from 0x23c (0-separated list, starting with 0, ending with 0)
# offsets into this list start from 0x198 + n * 0x10:    
#
# 0x198: 0x15  sigaction     -> 0x23d
# 0x1a8: 0x33  gettimeofday  -> 0x25b
# 0x1b8: 0x46  strcat        -> 0x26e
# 0x1c8: 0x40  srand         -> 0x268
# 0x1d8: 0x24  strlen        -> 0x24c
# 0x1e8: 0x41  rand          -> 0x269
# 0x1f8: 0x4d  printf        -> 0x275
# 0x208: 0x1f  exit          -> 0x247
# 0x218: 0x2b  strncat       -> 0x253
#                                                        
# we only need to tweak these to *create* the challenge, solving it requires no further adjustments
#


def list_replace(lst, old, new):   # O(N) but that is fine
   for i in range(len(lst)):
      if lst[i] == old:  lst[i] = new


import sys

if len(sys.argv) < 3:
   print("usage: python3 create.py infile outfile")
   exit(1)

# read input
with open(sys.argv[1], "rb") as f:
   binary = f.read()


# find offset of lib.c.so and GLIBC_2.0, and read symbols in between in .dyn.str

start = b"sigaction"
end = b"GLIBC_2.0"

startPos = binary.find(start, 0)
endPos   = binary.find(end, startPos)

symbols = binary[startPos:endPos].split(b"\x00")

print("symbols: ", symbols)

print("len=%d, %d" % (endPos - startPos, sum([len(v)+1 for v in symbols]) ) )

# modify symbols strlen, strncat, srand, rand, strcat, printf   - insert 5 bytes in total
#                gettimeofday -> getchar


list_replace(symbols, b"strlen", b"strlen\x03")
list_replace(symbols, b"strncat", b"strncat\x02")
list_replace(symbols, b"srand", b"srand\x01")  # takes care of rand as well
list_replace(symbols, b"strcat", b"strcat\x01")
list_replace(symbols, b"printf", b"printf\x04")
list_replace(symbols, b"gettimeofday", b"getchar")

print("symbols: ", symbols)

# write modification back to .dyn.str

newbytes = b"\x00".join([v for v in symbols])

print(newbytes)
print("len=%d, %d" % (endPos - startPos, len(newbytes)) )

binary = bytearray(binary)
for i in range(len(newbytes)):
   binary[i + startPos] = newbytes[i]

# update offsets in .dyn.sym

offspos = 0x1b8   # FIXME: hardcoded, and note that the order is different than in the symbol list)
offs_names = [b"strcat", b"srand", b"strlen", b"rand", b"printf", b"exit", b"strncat"]
for i,v in enumerate(offs_names):
   offs = binary.find(v) - 0x228
   binary[offspos] = offs
   offspos += 0x10
   

# save to outfile

with open(sys.argv[2], "wb") as f:
   f.write(binary)


