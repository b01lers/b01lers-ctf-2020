import sys, base64, binascii, string, numpy as np

#encodings/ciphers

# rot13 + capitalization
def rot13(s):
   s = s.upper()
   ret = ""
   for c in s:
      if c < 'A' or c > 'Z':
         ret += c
      else:
         ret += chr( (ord(c) - ord('A') + 13) % 26 + ord('A') )
   return ret

# Atbash + capitalization
def Atbash(s):
   s = s.upper()
   ret = ""
   for c in s:
      if c < 'A' or c > 'Z':
         ret += c
      else:
         ret += chr(25 - (ord(c) - ord('A')) + ord('A') )
   return ret

# Caesar + capitalization
def Caesar(s, shft):
   s = s.upper()
   ret = ""
   for c in s:
      if c < 'A' or c > 'Z':
         ret += c
      else:
         ret += chr((ord(c) - ord('A') + shft) % 26 + ord('A') )
   return ret

# Hill's cipher (inverse alg is same, use modular inverse of key matrix)
def hills(s, rows):
   # key matrix (A=0, B=1, ...)
   n = len(rows[0])
   kmatrix = np.zeros((n, n), dtype = int)
   for i in range(n):
      kmatrix[i] = [ord(c) - ord('A') for c in rows[i].upper()]
   # message vector (A=0, B=1, ...), pad with X
   s = s.upper()
   while (len(s) % n) != 0:
      s += "X"
   svec = np.zeros((len(s),), dtype = int)
   for i in range(len(s)):
      svec[i] = ord(s[i]) - ord('A')
   # encode
   ret = ""
   for i in range(0, len(svec), n):
      for k in range(n):
         code = np.dot(kmatrix[k], svec[i:(i+n)]) % 26
         ret += chr(code + ord('A'))
   # return
   return ret

   
# Morse, reencoded with o-O-0
def morse(s):
   s = s.upper()
   # dictionary
   dict = { "A": ".-",          # international Morse code
            "B": "-...",
            "C": "-.-.",
            "D": "-..",
            "E": ".",
            "F": "..-.",
            "G": " --.",
            "H": "....",
            "I": " ..",
            "J": " .---",
            "K": "-.-",
            "L": ".-..",
            "M": "--",
            "N": "-.",
            "O": "---",
            "P": ".--.",
            "Q": "--.-",
            "R": ".-.",
            "S": "...",
            "T": "-",
            "U": "..-",
            "V": "...-",
            "W": ".--",
            "X": "-..-",
            "Y": "-.--",
            "Z": "--..",
            ".": ".-.-.-",
            ",": "--..--",
            ":": "---..." }
   # encode
   ret = ""
   for c in s:
      k = dict.get(c)
      if k == None:
         ret += "   "
      else:
         ret += k + " "
   # reencode with o-O-0
   for c,d in zip(".- ", "oO0"):
      ret = ret.replace(c, d)
   return ret

# hex
def myhex(s):
   return binascii.hexlify(s)

# base64
def b64(s):
   return base64.b64encode(s)

# ascii85 -> much more widespread (but still has variants)
def a85(s):
   return base64.a85encode(s)

# letter sort
def sortWord(w):
   chars = [c for c in w]
   chars.sort()
   return "".join(chars)

def letterSort(s):
   words = [sortWord(w) for w in s.split(" ")]
   return " ".join(words)

# tap encoding (e.g., flip phones)
tapMap = {}   # map ascii code to tap string (key x n)

def buildTapMap():
   tapMap[ord(" ")] = "#"
   tapMap[ord(".")] = "1x1"
   tapMap[ord("0")] = "0"                                                                    #fake end
   keys = [(2, "A"),  (3, "D"), (4, "G"), (5, "J"), (6, "M"), (7, "P"), (8, "T"), (9, "W"), (0, "Z")]
   for i,(k,v) in enumerate(keys[:-1]):
      vend = keys[i + 1][1]
      cnt = 1
      while True:      
         tapMap[ord(v)] = str(k) + "x" + str(cnt)
         v = chr(ord(v) + 1)
         cnt += 1
         if v == vend:
            tapMap[ord(str(k))] = str(k) + "x" + str(cnt)
            break

def tap(s):
   if len(tapMap) == 0:  buildTapMap()
   s = s.upper()
   codes = []
   for c in s:
      val = tapMap.get(c)
      if val == None:   val = "?"
      codes.append(val)
   return " ".join(codes)



#TESTS
#print(rot13("abcd efghijklmnop qrs tuvwxyz"))
#print(Atbash("abcd efghijklmnop qrs tuvwxyz"))
#print(Caesar("abcd efghijklmnop qrs tuvwxyz", 3))
#print(morse("dead beed cba"))
#print(myhex(b"abcd efghijklmnop qrs tuvwxyz"))
#print(b64(b"abcd efghijklmnop qrs tuvwxyz"))
#print(letterSort("Attack at DAWN!!"))


# CHALLENGE

#verticals
c1 = b"Spelled backwards: command to adjust what belongs to whom on UNIX."
c2 = "THE SMALLEST RSA EXPONENT EVER IN WIDESPREAD USE."
c3 = b"Backwards: two for binary, ten for decimal, and sixteen for hex. "
c4 = "Possibly the first JavaScript function you ever called."
c5 = "Electronic documents that prove ownership of keys, reduced to five letters."
#horizontals
c6 = "Common reserved word in C++ and Python."
c7 = b"Modern crypto especially likes groups of prime _____."
c8 = "First half of a famous OpenSSL vulnerability."
c9 = b"Same as answer number five."


# completed grid:
#
#   1 2 3 4 5
#   N T X A C
# 6 W H I L E
# 7 O R D E R
# 8 H E A R T
# 9 C E R T S



# encrypt flag and clues

flag = "MESSAGEXISXNOXBLACKXSQUARESXAMIGOXSEPARATEDXBYXSPACEXANDXENCLOSEDXINXTHEXUSUALXFORMAT"


print(b"1: " + a85(c1))
print("2: " + rot13(c2))
print(b"3: " + myhex(c3))
print("4: " + Atbash(c4))
print("5: " + letterSort(c5))
print("6: " + Caesar(c6, 3))
print(b"7: " + b64(c7))
print("8: " + morse(c8))
print("9: " + tap(c9))


# matrix
M_rows = ["ntxac", "while", "order", "heart", "certs"]

# inverse matrix - computed on the side with a linalg package
# (same as the usual matrix inverse, except with modular
#  inverse for the 1/det(M) factor)
Minv_rows = ["ljgcp", "jjrrc", "hkbjb", "zqlxy", "kbjip"]


print("c=M*p:", hills(flag, M_rows) )
print("c=Minv*p:", hills(flag, Minv_rows) )

