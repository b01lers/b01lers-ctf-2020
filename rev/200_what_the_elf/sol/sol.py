# Author: dm

# The Linux loader complains that something is up with relocation information, regarding the function strncat. 
# Which is strange because it is a standard part of glibc. However, upon closer inspection (such as by "nm -D 
# whattheelf | hexdump -C", or "readelf -a whattheelf", or even just "./whattheelf | hexdump -C"), one may 
# notice that there are erroneous characters in there, so the missing function is NOT strncat. In fact, most 
# dynamically linked function names end on spurious 0x01 - 0x04 characters.
#
# A quick fix is to simply hex edit the relevant strings in the ELF file. The strings start with 'strlen\x03' at 
# offset 0x24c. The beginning of each string must stay at the same byte position but the extra character can be 
# cut, replaced by zero in fact, to keep the names properly zero-terminated. Once those 5 bytes are fixed, the 
# binary is runnable and gives the flag.
#
#
# The python code below does the editing, and prints the flag.


import os


# read binary
with open("whattheelf", "rb") as f:
   binary = f.read()


binary = bytearray(binary)

binary[0x252] = 0
binary[0x25b] = 0
binary[0x26a] = 0
binary[0x272] = 0
binary[0x27a] = 0


# save patched binary
with open("whattheelf-fix", "wb") as f:
   f.write(binary)

# run it
os.system("chmod +x whattheelf-fix")
os.system("./whattheelf-fix")

#EOF
