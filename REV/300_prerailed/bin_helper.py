import sys
import re

binre = "0[Bb][01]+"
hexre = "0[Xx][a-fA-F0-9]+"

if re.match(binre, sys.argv[1]):
    val = int(sys.argv[1], 2)
    print(hex(val))
elif re.match(hexre, sys.argv[1]):
    val = int(sys.argv[1], 16)
    print(bin(val))