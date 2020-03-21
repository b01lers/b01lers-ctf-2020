# Author: dm

# take multiple computer-assisted passes: first reconstruct unambiguous characters (and thus identify the 
# language), then do a few language-specific passes to get/complete individual lines, then order those lines 
# sensibly, and finally run the code. It makes no sense to automate things completely.

import sys, string
from PIL import Image, ImageDraw


#map chars to punch pattern
#                   cc0123456789
punchTbl = { ' ': 0b000000000000,
             #0-9 
             '0': 0b001000000000,
             '1': 0b000100000000,
             '2': 0b000010000000,
             '3': 0b000001000000,
             '4': 0b000000100000,
             '5': 0b000000010000,
             '6': 0b000000001000,
             '7': 0b000000000100,
             '8': 0b000000000010,
             '9': 0b000000000001,
             #A-Z
             'A': 0b100100000000,
             'B': 0b100010000000,
             'C': 0b100001000000,
             'D': 0b100000100000,
             'E': 0b100000010000,
             'F': 0b100000001000,
             'G': 0b100000000100,
             'H': 0b100000000010,
             'I': 0b100000000001,
             'J': 0b010100000000,
             'K': 0b010010000000,
             'L': 0b010001000000,
             'M': 0b010000100000,
             'N': 0b010000010000,
             'O': 0b010000001000,
             'P': 0b010000000100,
             'Q': 0b010000000010,
             'R': 0b010000000001,
             'S': 0b001010000000,
             'T': 0b001001000000,
             'U': 0b001000100000,
             'V': 0b001000010000,
             'W': 0b001000001000,
             'X': 0b001000000100,
             'Y': 0b001000000010,
             'Z': 0b001000000001,
             #specials
             '#': 0b000001000010,
             ',': 0b001001000010,
             '$': 0b010001000010,
             '.': 0b100001000010,
             '-': 0b010000000000,
             '@': 0b000000100010,
             '%': 0b001000100010,
             '*': 0b010000100010,
             '<': 0b100000100010,
             '/': 0b001100000000,
             '+': 0b100000001010,
             '_': 0b001000010010,
             ')': 0b010000010010,
             # skipped cent
             '|': 0b100000000110,
             '>': 0b001000001010,
             ':': 0b000010000010,
             ';': 0b010000001010,
             # skipped negation and degree
             '?': 0b001000000110,
             '"': 0b000000000110,
             '=': 0b000000001010,
             '!': 0b010010000010,
             '(': 0b100000010010   }

# reverse map (holes to char)
readTbl = { punchTbl[e]: e for e in punchTbl}


## READING CARDS
##

def getBox(pos, bit):
   #  0,0 =   50, 137
   # 79,9 = 1421, 591
   dx = (1421 - 50) / 79
   dy = (591 - 137) / 9
   x = 50 - 10 + dx * pos
   y = 591 - dy * bit
   return ((x+dx*0.3,y), (x+dx*0.9, y+dy*0.4))
  
PUNCHcol = (64, 64, 64)

# determine whether a given boxed area is filled (i.e., punched) on image
# uses average pixel color
def isFilled(box, img):
   #img = img.convert("RGB")
   # check how uniform the box is
   tl = box[0]
   br = box[1]
   # average pixel
   tot = (0, 0, 0)
   for x in range(int(tl[0]), int(br[0])):
      for y in range(int(tl[1]), int(br[1])):
         p = img.getpixel((x,y))
         tot = (tot[0] + p[0], tot[1] + p[1], tot[2] + p[2])
   fac = 1. / ( (br[0] - tl[0]) * (br[1] - tl[1]) )
   avp = (tot[0] * fac, tot[1] * fac, tot[2] * fac)
   # deviation from punchhole color (L1 norm / 3)
   d = 0
   for i in range(3):
      d += abs(avp[i] - PUNCHcol[i])
   d /= 3
   # accept if < 10
   return d < 10

# read punch pattern at given position on given image
def read(pos, img):
  pat = 0
  msk = 1
  for b in range(12):
     box = getBox(pos, b)  
     if isFilled(box, img):
        pat |= msk        
     msk <<= 1
  return pat

# read punchcard, fill in ambiguous punches with 'amb'
def readAll(img, amb = "*"):
   w = ""
   for pos in range(79):
      pat = read(pos, img)
      c = readTbl.get(pat) 
      if c == None:
         c = amb
      w += c
   return w

# find all two-character possibilities at each position on given punchcard
def readFuzzyAll(img):
   ret = []
   for pos in range(79):
      pat = read(pos, img)
      opt = {}
      for e in readTbl:
         if (pat & e) == e:
            opt[e] = readTbl[e];
      pair = []
      for e1 in opt:
         for e2 in opt:
            if (e1 | e2) == pat:
              if e1 == e2:
                 pair.append(readTbl[e1])
              else:
                 pair.append(readTbl[e1] + readTbl[e2])
      # reorder to move alphabetic answers first
      pairOrd = []
      for p in pair:
          if p.isalpha() or (len(p) == 1):
             pairOrd.insert(0, p)
          else:
             pairOrd.append(p)
      ret.append(pairOrd)
   return ret


## ANALYZING CARD DATA ("combinations")

# find possible word matches at beginning position
# from a given dictionary
def findNext(comb, dict):
   ret = []
   for s in dict:
      match = True
      for i in range(len(s)):
         c = s[i]
         cmatch = False
         for v in comb[i]:
            if c in v:
               cmatch = True
               break
         if cmatch == False:
            match = False
            break
      if match:
         ret.append(s)
   ret.sort(key=len, reverse=True)
   return ret


# reconstruct from "combinations" both lines on a card, 
# given a guess for the beginning of one of the lines
def deduceBoth(comb, guess, prfx = ""):
   lst = []
   # go though each position
   n = len(comb)
   for i in range(n):
      if i < len(guess):
         c = guess[i]
      else:
         c = " "
      # collect potential matches for second line
      matches = []
      for v in comb[i]:
         if c == v[0]:
            matches.append(v[-1])
      # sort order/preference: space, letters, punctuation, numbers
      matchOrdered = []
      if " " in matches:
         matchOrdered.append(" ")
      for c in string.ascii_uppercase:
         if c in matches:
            matchOrdered.append(c)
      for c in string.digits:
         if c in matches:
            matchOrdered.append(c)
      for c in matches:
         if not c in matchOrdered:
            matchOrdered.append(c)
      lst.append("".join(matchOrdered))
   # print solutions
   print(prfx, guess)
   idx = 0
   while True:
      w2 = ""
      printed = False
      for m in lst:
         if len(m) > idx:
            w2 += m[idx]
            printed = True
         else:
            w2 += " "
      if printed:
         print(prfx, w2)
         idx += 1
         continue
      break
   return lst

         

#
# SOLVE CHALLENGE
#



# read images
images = []
for i in range(1,10):
   fn = "img" + str(i) + ".jpg"
   images.append([Image.open(fn), fn])


# PASS 0 - just reconstruct characters, print "*" at ambigous positions
#

print("\n==PASS 0:")

pass0 = []
for v in images:
   w = readAll(v[0], "*")
   pass0.append(w)
   print("CARD:", v[1], '"', w, '"')

# this should give the hints that:
#   i) this is COBOL code
#   ii) there are arrays MAPI & MAPO, and variables OUT & J
#   iii) positions 0-6 and 54-79 are empty on every card, so can be ignored


# for rest of the passes, build all possible two-character matches for each punched column
combinations = []
for v in images:
   w = readFuzzyAll(v[0])[7:53]
   combinations.append(w)



# PASS 1 - find possible leading commands on each card
#

# some typical COBOL words
CBLdict = [ 
          "WORKING-STORAGE", "PIC", "OCCURS", "TIMES", "VALUE",            # memory
          "INSPECT", "REPLACING", "ALL", "BY", "STRING", "DELIMITED",      # strings
          "UNSTRING", "TALLYING", "CHARACTER",
          "PERFORM", "UNTIL", "THRU", "COUNT", "VARYING", "FROM", "BY",    # loops
          "DIVISION", "PROCEDURE", "SECTION", "IDENTIFICATION", "PROGRAM-ID",
          "ENVIRONMENT", "CONFIGURATION", "DATA",
          "MOVE", "TO", "DISPLAY",                                         #load/print
          "MULTIPLY", "ADD", "SUBTRACT",                                   #some math
          "STOP", "RUN"                                                    #end
        ]

print("\n==PASS 1:")

def doPASS1(imgs, combs, dict):
   ret = []
   for im, c in zip(imgs, combs):
      w = findNext(c, dict)
      ret.append(w)      
      print(im[1], w)
   return ret

pass1 = doPASS1(images, combinations, CBLdict)

# this gives starting code word: 
#   on both lines for 5 cards 
#   on one line for 1 card

# refine it with additional heuristics
#                       "STOP" -> "STOP RUN."
#                       "IDENTIFICATION" -> "IDENTIFICATION DIVISION."
#                       "DATA" -> "DATA DIVISION."
#                       "PROCEDURE" -> "PROCEDURE DIVISION."
#                       "WORKING-STORAGE" -> "WORKING-STORAGE SECTION."
#                       etc

EXTdict = ["STOP RUN.", 
           "IDENTIFICATION DIVISION.", 
           "DATA DIVISION.",
           "PROCEDURE DIVISION.",  
           "WORKING-STORAGE SECTION.",  
           "INSPECT OUT REPLACING ALL MAPI(J) BY MAPO(J).",
           "01 OUT", 
           "01 J",
           "01 MAPI",
           "01 MAPO"]
CBLdict += EXTdict

print("==PASS 1b:")
pass1 = doPASS1(images, combinations, CBLdict)



# PASS 2 - repeat reconstruction using longest hint from PASS 1
#

print("\n==PASS 2:")

def doPASS2(combs, guesses):
   for (i,(c,w)) in enumerate(zip(combs, guesses), start=1):
      if len(w) > 0:
         deduceBoth(c, w[0], str(i) + ":") 
      else:
         print("--skip--")

doPASS2(combinations, pass1)



# PASS 3 - refine passes 1 & 2 with improved dictionaries
#

EXT2dict = [  "PROGRAM-ID. OLD-BUT-NOT-FORGOTTEN.",
              "02 S PIC X(5) OCCURS 6 TIMES VALUE \"ABCDE\".",
              "PERFORM REP ",
              "DISPLAY \"PCTF(\" OUT \")\".",
              "01 J PIC ",
              "01 MAPI PIC X(1) OCCURS 9 TIMES.",
              "02 MAPO PIC X(1) OCCURS 9 TIMES.",
              "MOVE \""
           ]

CBLdict += EXT2dict

print("\n==PASS 3:")
pass1 = doPASS1(images, combinations, CBLdict)
doPASS2(combinations, pass1)



# PASS 4 - refine PERFORM REP... line by finding valid COBOL words from all possible starting positions
#

print("\n==PASS 4:")

def doPASS4(img, comb, dict, rng = -1):
   if rng < 0:
      rng = len(comb)
   for i in range(rng):
      sys.stdout.write(str(i) + ": ");
      doPASS1([img], [comb[i:]], dict)

doPASS4(images[4], combinations[4], CBLdict)

print("==PASS 4b:")

EXT3dict = [ "PERFORM REP VARYING J FROM " ]
CBLdict += EXT3dict

doPASS4(images[4], combinations[4], CBLdict, 2)

print("==PASS 4c:")

EXT3dict = [ "PERFORM REP VARYING J FROM 1 BY " ]
CBLdict += EXT3dict

doPASS4(images[4], combinations[4], CBLdict, 2)

print("==PASS 4d:")

EXT3dict = [ "PERFORM REP VARYING J FROM 1 BY 1 UNTIL J=10." ]
CBLdict += EXT3dict

doPASS4(images[4], combinations[4], CBLdict, 2)

print("==PASS 4e:")

pass1 = doPASS1(images, combinations, CBLdict)
doPASS2(combinations, pass1)



# PASS 5
#
# so there is a variable MAP as well
# -> fix memory patterns

print("\n==PASS 5:")

EXT4dict = [ "01 MAP.",
             "02 MAPI PIC X(1) OCCURS 9 TIMES.",
             "02 MAPC PIC X(1) OCCURS 9 TIMES.",
             "01 J PIC 99" ]
CBLdict += EXT4dict
CBLdict.remove(pass1[3][0])
#CBLdict.remove(pass1[4][0])
	      
pass1 = doPASS1(images, combinations, CBLdict)
doPASS2(combinations, pass1)

# => CARD ORDER:  9, 2, 3, 4, 6, 1, 5, 7, 8 
#
# The reconstructed source code is pass5.cobc, which is almost correct
# and basically prints the flag (except for one letter substitution). One can
# just correct the flag by hand, or fix the ambiguity in the code (pass5fix.cobc).


#EOF
