from ctypes import *
from pwn import *

so_file = "/lib/x86_64-linux-gnu/libc.so.6"
libc_funcs = CDLL(so_file)

#p = process("./meshuggah")
p = remote("pwn.ctf.b01lers.com", 1003)
libc_funcs.srand(libc_funcs.time() + 2)

p.recvlines(3)

line_1 = (p.recvline()).split()[1].split("-")[1]
line_2 = (p.recvline()).split()[1].split("-")[1]
line_3 = (p.recvline()).split()[1].split("-")[1]

assert int(line_1) == libc_funcs.rand()
assert int(line_2) == libc_funcs.rand()
assert int(line_3) == libc_funcs.rand()

for i in range(96):
    p.sendline(str(libc_funcs.rand()))
    p.recvline()
    #sleep(.1)

print(p.recvall(timeout=5))
