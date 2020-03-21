flag="pctf{goodlang??}"

idx = 0
for c in flag:
    print("{:08b} 0x{:02x} {}".format(ord(c), ord(c), c))
    idx += 1
    if idx == 8:
        print()