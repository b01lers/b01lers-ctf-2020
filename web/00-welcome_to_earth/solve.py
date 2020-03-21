#!/usr/bin/env python3

# Scrambled flag from web.ctf.b01lers.com:1000/static/js/fight.js
flag = ["{hey", "_boy", "aaaa", "s_im", "ck!}", "_baa", "aaaa", "pctf"]

# Make an unscramble function based on the scrambled function
i = len(flag) - 1
while i >= 0:
    # Key of what to do (from the movie independence day)
    key = 'punch it'

    # n is the second index to swap
    n = ord(key[i]) % len(flag)
    print('Swap (i: ' + str(i) + ', n: ' + str(n) + '): ' + flag[i] + ' ' + flag[n])

    # Swap the two
    temp = flag[i]
    flag[i] = flag[n]
    flag[n] = temp

    i -= 1

# Print flag
print(''.join(flag))
