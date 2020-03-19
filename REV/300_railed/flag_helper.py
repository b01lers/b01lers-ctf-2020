flag="pctf{runATR41N}"

for c in flag:
    print("{:08b} 0x{:02x} {}".format(ord(c), ord(c), c))