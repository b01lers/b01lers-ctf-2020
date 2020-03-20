import z3

s = z3.Solver()
# Create 8-bit bitvectors for each of the 21 chars in the string.
chrlist = z3.BitVecs('c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 c11 c12 c13 c14 c15 c16 c17 c18 c19 c20 c21 c22', 8)

# Do a preliminary constraint that all characters must be ascii.
for char in chrlist:
    s.add(z3.And(0x20 < char, char < 0x7f))

def get_models(s):
    while s.check() == z3.sat:
        m = s.model()
        yield m
        s.add(z3.Or([sym() != m[sym] for sym in m.decls()]))


# add constraints from program:
# given values
s.add(chrlist[2] == ord('t'))
s.add(chrlist[9] == ord('c'))
s.add(chrlist[16] == ord('n'))
s.add(chrlist[21] == ord('z'))
s.add(chrlist[22] == ord('}'))

# some of these are new, TODO: add them back to the go prog
s.add(chrlist[5] == chrlist[2] - 1)
s.add(chrlist[2] ^ chrlist[3] == 18)
s.add(chrlist[1] == chrlist[9])
s.add(chrlist[1] == chrlist[7] - 1)
s.add(chrlist[12] == chrlist[13])
s.add(chrlist[19] ^ chrlist[21] == 0)
s.add(chrlist[14] - ord('0') + chrlist[6] - ord('0') == 8)
# 
s.add(chrlist[4] == chrlist[22] - 2)
s.add(chrlist[8] == chrlist[15])
s.add(chrlist[8] + 4 == chrlist[1])
s.add(chrlist[22] - chrlist[17] + 40 == chrlist[11])
s.add(chrlist[11] - chrlist[5] - chrlist[18] + chrlist[17] == chrlist[18] - chrlist[17])
s.add(chrlist[0] == chrlist[16] + ((chrlist[18] - chrlist[17]) * ((chrlist[6] - chrlist[17])  / 2)))
s.add(chrlist[10] == chrlist[13] + 1)
s.add(chrlist[10] == (((chrlist[4] - chrlist[7]) * 4) + (2 * (chrlist[6] - chrlist[17]))) + ((chrlist[6] - chrlist[17])))
s.add(2 * (chrlist[18] - chrlist[17]) == chrlist[20] - chrlist[1])
s.add(chrlist[5] ^ chrlist[16] == 29)
s.add(chrlist[6] - chrlist[17] == (chrlist[18] - chrlist[17]) * 4)
s.add(chrlist[6] == chrlist[14])
for m in get_models(s):
    print("".join([chr(m[char].as_long()) for char in chrlist]))