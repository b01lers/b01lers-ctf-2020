# Xwing Control

## Points:
flag1: 100, flag2: 200, flag3: 200, flag4: 300
## Description:
https://youtu.be/bYAoGTywR5c
## Creator:
nsnc

# Solve

In this challenge, all that you recieve is video. The relevant information in the video is:
 - 0:02 Website: http://xwing.pwn.ctf.b01lers.com
 - 0:05 Binary Ninja disassembly output (with addresses), checksec output
 - 0:13 cat /proc/xwing/maps output for a couple frames
 - 0:15 Source code for the commands hyperdrive, examine, and partial code for fix
 - 0:23 Partial hexdump of the binary, including the correct engine value, and the correct password.
 - 0:34 Examples of usage of the program

## Flag 1

Log in succesfully. At the beginning of the hexdump in the video is the text "LeiaIsCute". This is the password that can be used to authenticate
```
pctf{Im_afraid_the_battl3stati0n_iz_Fully_Operational...}
```

## Flag 2

Succesfully reach the Death Star. To do this, you need to fix the hyperdrive. Use the leak tool given, `examine`, to dump the entire binary. The maps at 13 seconds in on the video show where you need to read to dump the binary. Look at `dump-binary.py` for more details about the implementation. Then you can use `fix` to write to the engine line that is checked before enabling hyperdrive. You can now run `hyperdrive on` and increase your throttle enough to arrive at the Death Star.

## Flag 3

Succesfully defeat the Death Star. There are multiple ways to do this. The intended way was to use the long overwrite provided by `fix` to overwrite both `damage` and `distance` instead of fixing the engine. This will allow you to reach the Death Star immidiately, as well as deal enough damage to defeat the Death Star.

You may also be able to use `__malloc_hook` to jump to where the death star dies, or probably the easiest method: use `__free_hook` to call system('/bin/sh') and skip straight to final flag.

## Flag 4

The `logwin()` function has a heap buffer overflow when renaming xwings. Some heap feng shui must be used to ensure that the right Tie Fighters are freed so the allocated buffer will overwrite the next pointer of a freed xwing, which con be used to gain arbitrary write. The libc version used is `glibc-2.30` (In the Dockerfile liked by the website), which does not have any protections for this type of situation. This means some tie fighters should be killed before killing the Death Star. The arbitrary write given by the heap buffer overflow can be used to ROP and perform a ret2libc for a shell.
