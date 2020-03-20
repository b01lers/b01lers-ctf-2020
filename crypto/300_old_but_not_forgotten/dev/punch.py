import sys
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


def getBox(pos, bit):
   #  0,0 =   50, 137
   # 79,9 = 1421, 591
   dx = (1421 - 50) / 79
   dy = (591 - 137) / 9
   x = 50 - 10 + dx * pos
   y = 591 - dy * bit
   return ((x+dx*0.3,y), (x+dx*0.9, y+dy*0.4))
  
PUNCHcol = (64, 64, 64)

def punch(pat, pos, d):
   # from bit 9 down to control bits
   b = 0
   while (pat > 0):
      if (pat & 1) != 0:    
         d.rectangle(getBox(pos,b), fill = PUNCHcol)
      pat >>= 1
      b += 1
 
def punchAll(w, img): 
   draw = ImageDraw.Draw(img)
   pos = 0
   for c in w:
      pat = punchTbl[c]
      punch(pat, pos, draw)
      pos += 1
   return img


def pixelDiff(p1, p2): 
   ret = 0
   for a,b in zip(p1, p2):
      ret += abs(a - b)
   return ret   

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
   # return deviation from punchhole color (L1 norm / 3)
   d = 0
   for i in range(3):
      d += abs(avp[i] - PUNCHcol[i])
   return d / 3 < 10

def read(pos, img):
  pat = 0
  msk = 1
  for b in range(12):
     box = getBox(pos, b)  
     if isFilled(box, img):
        pat |= msk        
     msk <<= 1
  return pat

def readAll(img):
   w = ""
   for pos in range(79):
      pat = read(pos, img)
      w += readTbl[pat] 
   return w


# TEST write/read with singly-punched cards
def TEST1(img0):
   i = 0
   for l in sys.stdin:
      l = l.strip("\n")
      img = punchAll(l, img0.copy())
      img.save("out" + str(i) + ".jpg", "JPEG")
      i += 1
   for i in range(18):
      img = Image.open("out" + str(i) + ".jpg")
      w = readAll(img)
      print('"', w, '"')



# create challenge

img0 = Image.open("Punched card 094.jpg")

#TEST1(img0)

# write doubly-punched images
i = 0
n = 0
for l in sys.stdin:
   # read next odd and even line
   l2 = l.strip("\n")
   n = 1 - n
   if n == 1:
      l1 = l2
      continue
   # punch both on card, then save
   img = punchAll(l1, img0.copy())
   img = punchAll(l2, img)
   img.save("img" + str(i) + ".jpg", "JPEG")
   i += 1

#EOF
