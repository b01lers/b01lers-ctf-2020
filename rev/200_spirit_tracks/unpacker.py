import struct
import os
with open("memdump", "rb") as f:
    bytevals = f.read()[0x20:]
    for i in range(0, len(bytevals), 0x28):
        #print(hex(struct.unpack("<Q", bytevals[i:i+8])[0])[2:])