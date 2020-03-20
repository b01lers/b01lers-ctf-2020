# Blind Piloting

## Category
PWN
## Points:
flag1: 200, flag2: 200
## Description:
How well are you able to fly blindfolded?
## Creator:
nsnc

## Solve


Part one: Overwrite a LSB

Part two: Gain RCE

# Part 1

In this challenge, a short program with full protections is given:
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

The entire source code for the program is less than 50 lines long. It's behavior is simple: It will fork, and buffer overflow a child process.

The `fork()` system call copies the same memory to the child process. This means that the child and parent share the same stack canary. As such, it can be brute forced one byte at a time. See `solve.py` for an implementation of this brute force. One way to ensure this runs as quickly as possible is to use `p.recvuntil` to avoid extra timeouts.

Once the stack canary has been brute forced, we can overwrite the LSB of the return address to jump to the win function, which will print the first flag for us. I made a minor change to the program before releasing, however, so it might have been required to overwrite the two least singificant bits instead of the LSB.

# Part 2

Part two involves getting full code execution. I did this by brute forcing PIE. I attempted to figure out the address of `perror()` one byte at a time, starting at the LSB bytes, and moving to the more significant bytes.

Once PIE has been leaked, a ropchain can be used to leak libc and perform a ret2libc to call `system('/bin/sh')`. See solve.py for a full implementation of the exploit.

An alternative solution for part 2 could involve using a retchain and brute forcing a libc addresses. This will work, but requires performing a 12 bit brute force, in addition to some 8 bit brutes, which will take significantly longer than only brute forcing one byte at a time (About 2x as long).

My solve for both parts took a little more than one minute locally, and five minutes on the remote, but hardware optimization did begin to kick in at some point, so your results will likely be slower.

The full solution is visible in `solve.py`. Note that it is not stable, and may not work every time.
