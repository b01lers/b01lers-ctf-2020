import sys, collections, gzip
import numpy as np

##
## construct the most probable plaintexts assuming a Markov chain language model
## based on n-gram distributions up to n=4, stored in numpy arrays
##
## (as, e.g., in "A Natural Language Approach to Automated Cryptanalysis of Two-time 
##  Pads" by Mason, Watkins, Eisner, and Stubblefield,  presented at CCS2006,
##  but they go up to n=7, and use tries)
##


## read params
# usage: python3 sol-np.py [MAXbest [endpos [solFile1 [solFile2]]]]
#

print("#usage:  python3 sol-np.py [MAXbest [endpos [solFile1 [solFile2]]]]")


# number of solution candidates to keep in optimum search
MAXbest  = int(sys.argv[1]) if len(sys.argv) > 1  else 100

# ciphertext position to solve until
ENDpos   = int(sys.argv[2]) if len(sys.argv) > 3 else -1

# supply imposed solution from files
# - solver will try to match these, except for 'blank' characters (specified below)
solFileName1 = sys.argv[3]   if len(sys.argv) > 3   else  b""
solFileName2 = sys.argv[4]   if len(sys.argv) > 4   else  b""

BLANKchar = '#'

def readSolFile(fn):
   ret = b""
   if len(fn) > 0:
      with open(fn, "rb") as f:
         ret = f.read()
      print(len(ret))
      while ret and ret[-1] < 32:   # remove trailing newline (FIXME: crude)
         ret = ret[:-1]
   return ret

FIXEDsol1 = readSolFile(solFileName1)
FIXEDsol2 = readSolFile(solFileName2)


print("MAXbest=%d" % MAXbest)
print("ENDpos=%d" % ENDpos)
if len(FIXEDsol1) > 0:
   print("solFile1=%s, len=%d, BLANK=%s" % (sys.argv[3], len(FIXEDsol1), BLANKchar))
if len(FIXEDsol2) > 0:
   print("solFile2=%s, len=%d, BLANK=%s" % (sys.argv[4], len(FIXEDsol2), BLANKchar))


## read ciphertexts, xor them, and apply START/END cuts

with open("msg1.enc", "rb") as f:
   ctxt1 = f.read()

with open("msg2.enc", "rb") as f:
   ctxt2 = f.read()

cxor = bytearray()
for c,d in zip(ctxt1, ctxt2):
   cxor.append(c ^ d)

if ENDpos >= 0:
   cxor = cxor[:ENDpos]


## read dictionary and n-gram distributions up to n=4

print("# reading dict and n-gram data...")

# map for char -> array idx, and inverse map (array idx -> char)
dictBytes = b""
with open("dict.dat", "rb") as f:
   dictBytes = f.read()

dict1 = { chr(b):i for i,b in enumerate(dictBytes) }
invDict1 = { dict1[c]:c for c in dict1 }
n1 = len(dict1)

# print characters
lst1 = [k for k in dict1]
lst1.sort()
print(str(n1) + " chars: " + "".join(lst1))
print(ord(lst1[-1])) # highest ascii code

# n-grams
with gzip.open("P1wb.dat.gz", "rb") as f:
   P1wb = np.frombuffer(f.read(), dtype = float)

with gzip.open("P2wb.dat.gz", "rb") as f:
  P2wb = np.frombuffer(f.read(), dtype = float)
  P2wb.shape = (n1, n1)

with gzip.open("P3wb.dat.gz", "rb") as f:
   P3wb = np.frombuffer(f.read(), dtype = float)
   P3wb.shape = (n1,n1,n1)

with gzip.open("P4wb_s.dat.gz", "rb") as f:        # read single-prec data
   P4wb = np.frombuffer(f.read(), dtype = np.float32)
   P4wb.shape = (n1,n1,n1,n1)
   P4wb = np.float64(P4wb)               # convert array to double precision


## decipher original plaintexts

print("# decipher ptxt1 and ptxt2...")

# get idx of char in ctxt2, given idx of char in ctxt1 and xor value
def getIdx2slow(i, b):
   ki = invDict1[i]
   ki2 = chr(ord(ki) ^ b)
   i2 = dict1.get(ki2)
   return i2  if  i2 != None  else -1

# build lists of viable index pairs - for SPEEDUP
idxPairs = []
for b in range(256):
   lst = []
   for i in range(n1):
      i2 = getIdx2slow(i, b)
      if i2 >= 0:
         lst.append((i, i2))
   idxPairs.append(lst)

# score a solution candidate - returns log(P) -> for testing
def score(ptxt1, cxor):
   ptxt2 = bytes( [ p1 ^ b for p1,b in zip(ptxt1, cxor)]  )
   print(ptxt1, ptxt2)
   lnP = 0.
   i,  j,  k,  l  = 0, 0, 0, 0
   i2, j2, k2, l2 = 0, 0, 0, 0
   for pos,(p1,p2) in enumerate(zip(ptxt1, ptxt2)):
      l, l2 = k, k2
      k, k2 = j, j2
      j, j2 = i, i2
      i, i2 = dict1[chr(p1)], dict1[chr(p2)]
      if pos == 0:
         lnP += P1wb[i] + P1wb[i2]
      elif pos == 1:
         lnP += P2wb[j][i] + P2wb[j2][i2]
      elif pos == 2:
         lnP += P3wb[k][j][i] + P3wb[k2][j2][i2]
      # 4-grams from 3rd position and on
      elif pos >= 3:
         lnP += P4wb[l][k][j][i] + P4wb[l2][k2][j2][i2]
   return lnP

#print(score(b"this", cxor))


# track Nbest most probable completion candidates
#
# storage scheme:
#   solsIdx[s][p] gives the index pair at p-th position in the s-th candidate
#   solsP[s] gives the log likelihood for the s-th candidate

Nxor = len(cxor)

solsIdx = np.zeros((MAXbest, Nxor, 2), dtype = int)  
solsP = np.zeros(MAXbest) 

# initialize (starting from a single empty string candidate)
Nbest = 1
solsP[0] = 0.   # P = 1 => log(P) = 0

# print top topN candidates as strings
def printSolutions(endpos, topN):
   for s in range(topN):
      ptxt1 = ""
      ptxt2 = ""
      for p in range(endpos):
         (i, i2) = solsIdx[s][p]
         ptxt1 += invDict1[i]
         ptxt2 += invDict1[i2]
      print(str(s) + ": " + ptxt1)
      print(str(s) + ": " + ptxt2)
      print("(len=%d),  ln P =%f" % (len(ptxt1), solsP[s]) )


# construct candidates one char at a time
# by stepping through xored ciphertext 
for pos in range(Nxor):
   # find next best continuations
   # nxt[s] is a tuple: (likelihood, cand to append to, (i, i2) of continuation chars))
   b = cxor[pos]
   pairs = idxPairs[b]
   # impose specified solution, if any, by restricting pool of pairs
   p1 = chr(FIXEDsol1[pos]) if pos < len(FIXEDsol1)  else BLANKchar     # sol1 char to impose
   p2 = chr(FIXEDsol2[pos]) if pos < len(FIXEDsol2)  else BLANKchar     # sol2 char to impose
   if p1 != BLANKchar:
      i1 = dict1[p1]
      pairs = [(i,j) for (i,j) in pairs  if  i == i1]    # restrict pool, if possible - FIXME: would be faster to precompute these
   if p2 != BLANKchar:
      i2 = dict1[p2]
      pairs = [(i,j) for (i,j) in pairs  if  j == i2]    # restrict pool, if possible
   if not pairs:                        # if no solution, ignore constraints (restore pool)
      pairs = idxPairs[b]
   # explore pool
   nxt = []
   for s in range(Nbest):
      prevP   = solsP[s]
      prevIdx = solsIdx[s]
      # use 1-grams at 0-th position
      if pos == 0:
         for (i,i2) in pairs:
            if i <= i2 or len(pairs) == 1:  # eliminate ptxt1<->ptxt2 interchange solutions
               nxt.append( (P1wb[i] + P1wb[i2], s, (i, i2)) )
      # 2-grams at 1st position
      elif pos == 1:
         (j, j2) = prevIdx[pos - 1]
         for (i, i2) in pairs:
            nxt.append( (prevP + P2wb[j][i] + P2wb[j2][i2], s, (i, i2)) )
      # 3-grams at 2nd position
      elif pos == 2:
         (k, k2) = prevIdx[pos - 2]
         (j, j2) = prevIdx[pos - 1]
         for (i, i2) in pairs:
            nxt.append( (prevP + P3wb[k][j][i] + P3wb[k2][j2][i2], s, (i, i2) ) )
      # 4-grams from 3rd position and on
      else :
         (l, l2) = prevIdx[pos - 3]
         (k, k2) = prevIdx[pos - 2]
         (j, j2) = prevIdx[pos - 1]
         for (i, i2) in pairs:
            nxt.append( (prevP + P4wb[l][k][j][i] + P4wb[l2][k2][j2][i2], s, (i, i2) ) )
   nxt.sort(key = lambda v: -v[0]) # sort by decreasing probability
   nxt = nxt[:MAXbest]
   Nbest = len(nxt)
   # update solution indices - FIXME: there must be a more efficient way...
   tmpIdx = np.zeros((Nbest, pos, 2))  # create new best sequences in temporary storage
   for s in range(Nbest):
      olds = nxt[s][1]     
      for q in range(pos):
         tmpIdx[s][q] = solsIdx[olds][q]
   for s in range(Nbest):          # copy temporary to solution array
      for q in range(pos):
         solsIdx[s][q] = tmpIdx[s][q]
      solsIdx[s][pos] = nxt[s][2]  # append idx pair added in this round
      solsP[s] = nxt[s][0]         # update likelihood
   # progress indicator
   if pos % 10 == 0:     
      printSolutions(pos + 1, 1)
      sys.stdout.flush()

print("#")
print("# best up to " + str(MAXbest) + " solutions:")
print("#")
printSolutions(Nxor, Nbest)

