import struct
import os

# Generate mappings with solve.c / hash.s and remove the opening / closing braces
map_vals = open("mappings", "r")
lines = map_vals.readlines()
mapping = {}
for line in lines:
    line = line[:len(line) - 2]
    vals = line.split(":")
    mapping[(int(vals[0], 16))] = vals[1]

with open("memdump", "rb") as f:
    bytevals = f.read()[0x20:]
    flag = ""
    for i in range(0, len(bytevals), 0x28):
        num = (struct.unpack("<Q", bytevals[i:i+8])[0])
        try:
            flag += mapping[num]
        except:
            print(flag)
            break
        
