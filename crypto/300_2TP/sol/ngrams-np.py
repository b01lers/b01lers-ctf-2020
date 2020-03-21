import sys, collections, gzip
import numpy as np

##
## collect n-gram distributions from sample text on stdin
##
## this could be done better with natural language processing tools such as LingPipe
## we roll our own for simplicity, up to n=4
## - the main deficiency is in memory footprint (arrays here vs tries there)
##


# remove control chars and ascii > 127 from sample texts - FIXME: super crude
txt = sys.stdin.read()
txt = "".join( [c if (ord(c) >= 32 and ord(c) < 128) else " " for c in txt] )

#for c in ";,?!0123456789#$%&*+/<=>@|:'`()[]_\/{}-\"":
#   txt = txt.replace(c, "")

#txt = txt.lower()


# 1-gram likelihoods
# - keep only nonzero counts => use dictionary, then convert to numpy array
# - use Witten-Bell smoothing
#
#   P1_WB(i) = Ntot/(Ntot + N1+) * N(i)/Ntot + N1+/(Ntot + N1+) * p0
#            = (N(i) + 1) / (Ntot + N1+)
# 
#   where Ntot is the sum of 1-gram counts
#         N1+  is the number of 1-gram types with at least 1 count
#         N(i) is the count for (i) 1-grams
#         p0   is the fallback distribution (chosen uniform)  -> 1/N1+

print("#1-gram likelihoods...")

dict1 = {}

for c in txt:
   if dict1.get(c) == None:
      dict1[c] = 1
   else:
      dict1[c] += 1

# convert to probabilities, use WB smoothing
n1 = len(dict1)    # size of observed alphabet = N1p
N1tot = len(txt)   # total 1-grams
for k in dict1:
   c = dict1[k]
   dict1[k] = (c + 1) / float(n1 + N1tot)

# order dictionary by decreasing probability
dict1 = collections.OrderedDict(sorted(dict1.items(), key = lambda v: -v[1]))

# print characters found
lst1 = [k for k in dict1]
lst1.sort()
print(str(n1) + " chars: " + "".join(lst1))
print(ord(lst1[-1])) # highest ascii code
#print(dict1)

# copy 1-gram prob dictionary to numpy array
# convert 1-gram prob dict to a map to array index:  dict1[k] -> i
P1wb = np.zeros(n1)
invDict1 = {}
for i,k in enumerate(dict1):
   P1wb[i] = dict1[k]
   dict1[k] = i


diff1 = abs(P1wb.sum() - 1.)
print("diff1 = " + str(diff1))


# 2-gram likelihood P2(ji) = probability for (ji) given (j)
# - construct all n1^2 2-grams, use numpy array
# - apply WB smoothing
#
#   P2_WB(ji) = Ntot(j)/[Ntot(j) + N1+(j)] * N(ji)/Ntot(j) + N1+(j)/[Ntot(j) + N1+(j)] * p0(ji)
#              = N(ji) / [Ntot(j) + N1+(j)] + N1+(j)/[Ntot(j) + N1+(j)] * P1_WB(i)
# 
#   where Ntot(j) is the sum of (j*) 2-gram counts
#         N1+(j)  is the number of 2-gram types (j*) with at least 1 count
#         N(ji)   is the count for (ji) 2-grams
#         p0(ji)  is the fallback distribution, chosen to be P1_WB(i) independently of j

print("#2-gram likelihoods...")

# raw counts
P2wb = np.zeros((n1, n1))
for cj,ci in zip(txt[:-1], txt[1:]):
   j = dict1.get(cj)
   i = dict1.get(ci)
   P2wb[j][i] += 1

# convert to probs, apply WB smoothing
for j in range(n1):
   N2tot = P2wb[j].sum()
   if N2tot == 0.:
      P2wb[j] = P1wb
      continue
   N2p = (P2wb[j] > 0.).sum()
   P2wb[j] += N2p * P1wb
   P2wb[j] *= 1. / float(N2p + N2tot)


diff2 = abs(P2wb.sum(axis = 1) - 1.).max()
print("diff2 <= " + str(diff2))


# 3-gram likelihood P3(kji) = probability for (kji) given (kj)
# - construct all n1^3 3-grams, use numpy array
# - apply WB smoothing
#
#   P3_WB(kji) = Ntot(kj)/[Ntot(kj) + N1+(kj)] * N(kji)/Ntot(kj) + N1+(kj)/[Ntot(kj) + N1+(kj)] * p0(kji)
#              = N(kji) / [Ntot(kj) + N1+(kj)] + N1+(kj)/[Ntot(kj) + N1+(kj)] * P2_WB(ji)
# 
#   where Ntot(kj) is the sum of (kj*) 3-gram counts
#         N1+(kj)  is the number of 3-gram types (kj*) with at least 1 count
#         N(kji)   is the count for (kji) 3-grams
#         p0(kji)  is the fallback distribution, chosen to be P2_WB(ji) independently of k

print("#3-gram likelihoods...")

# raw counts
P3wb = np.zeros((n1, n1, n1))
for ck,cj,ci in zip(txt[:-2], txt[1:-1], txt[2:]):
   k = dict1.get(ck)
   j = dict1.get(cj)
   i = dict1.get(ci)
   P3wb[k][j][i] += 1

# convert to probs, apply WB smoothing
for k in range(n1):
   for j in range(n1):
      P3kj = P3wb[k][j]
      N3tot = P3kj.sum()       # sum elements
      if N3tot == 0.:
         P3wb[k][j] = P2wb[j]
         continue
      N3p = (P3kj > 0.).sum()  # count positive elements
      P3wb[k][j] += N3p * P2wb[j]
      P3wb[k][j] *= 1. / float(N3tot + N3p)

diff3 = abs(P3wb.sum(axis = 2) - 1.).max()
print("diff3 <= " + str(diff3))


# 4-gram likelihood P4(lkji) = probability for (lkji) given (lkj)
# - construct all n1^4 4-grams, use numpy array
# - apply WB smoothing
#
#   P4_WB(lkji) = Ntot(lkj)/[Ntot(lkj) + N1+(lkj)] * N(lkji)/Ntot(lkj) + N1+(lkj)/[Ntot(lkj) + N1+(lkj)] * p0(lkji)
#               = N(lkji) / [Ntot(lkj) + N1+(lkj)] + N1+(lkj)/[Ntot(lkj) + N1+(lkj)] * P3_WB(kji)
# 
#   where Ntot(lkj) is the sum of (lkj*) 4-gram counts
#         N1+(lkj)  is the number of 4-gram types (lkj*) with at least 1 count
#         N(lkji)   is the count for (lkji) 4-grams
#         p0(lkji)  is the fallback distribution, chosen to be P3_WB(kji) independently of l

print("#4-gram likelihoods...")

# raw counts
P4wb = np.zeros((n1, n1, n1, n1))
for cl,ck,cj,ci in zip(txt[:-3], txt[1:-2], txt[2:-1], txt[3:]):
   l = dict1.get(cl)
   k = dict1.get(ck)
   j = dict1.get(cj)
   i = dict1.get(ci)
   P4wb[l][k][j][i] += 1

# convert to probs, apply WB smoothing
for l in range(n1):
   for k in range(n1):
      for j in range(n1):
         P4lkj = P4wb[l][k][j]     # sum elements
         N4tot = P4lkj.sum()
         if N4tot == 0.:
            P4wb[l][k][j] = P3wb[k][j]
            continue 
         N4p = (P4lkj > 0.).sum()  # count positive elements
         P4wb[l][k][j] += N4p * P3wb[k][j]
         P4wb[l][k][j] *= 1. / float(N4p + N4tot)

diff4 = abs(P4wb.sum(axis = 3) - 1.).max()
print("diff4 <= " + str(diff4))

## stop at n=4, no 5-grams and beyond


## convert likelihood arrays to log-likelihood

print("# convert to log(P)")

P1wb = np.log(P1wb)
P2wb = np.log(P2wb)
P3wb = np.log(P3wb)
P4wb = np.log(P4wb)


## output dictionary and n-gram likelihoods

print("# writing files...")

dictArr = bytearray( [ord(c) for c in dict1] )

with open("dict.dat", "wb") as f:
   f.write(dictArr)

with gzip.open("P1wb.dat.gz", "wb") as f:
   f.write(P1wb)

with gzip.open("P2wb.dat.gz", "wb") as f:
   f.write(P2wb)

with gzip.open("P3wb.dat.gz", "wb") as f:
   f.write(P3wb)

# n=4 arrays can get large O(0.5 GB) with full double precision,
# so save those in single precision instead
with gzip.open("P4wb_s.dat.gz", "wb") as f:
   P4wb = np.float32(P4wb)
   f.write(P4wb)

##END
