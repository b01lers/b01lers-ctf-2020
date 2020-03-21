# correct decoding, uses correct phi (obtains factors of N)
#

N = 22518213392401264818411278544481843914232432830458541414885458377878266793498750772354592395933629538430168704357367677366063506437840746114109698561818213653155337516332045907584538560207347457518815750143165409925001430273241092541136748646685328169745125245340633556971837060802857356695229674488893860374426117801802327059524160107136439418599365088385458686062313445632037797173490869675537943240896233769936787893899596578453468394750636934950285496609730610849908463004889068961426952923099134018106324063391090991215384284497435868352255958362702412123106399579166856780539143530223177815706341761329346665123
phi = 22518213392401264818411278544481843914232432830458541414885458377878266793498750772354592395933629538430168704357367677366063506437840746114109698561818213653155337516332045907584538560207347457518815750143165409925001430273241092541136748646685328169745125245340633556971837060802857356695229674488893860374125936771634231083724519781739692120840798867536892089959731316847037589936959996408416801992484839541189805041461052140389233753983174954128996839480404891785287303195083960639773803194332300000270420399549292186960561461628916388255677931409154971065184660947084539883190976066572465271852306890113256664720
e = 65537


import sys, gmpy2


def gcd(x, y) :
   while x != 0 :
      x,y = y % x, x
   return y

def xgcd(b, a):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

def modinv(a, n) :
  g, x, y = xgcd(a, n)
  if g != 1 :
    return 0
  return x % n


def decrypt(c):
   return pow(c, d, N)


# It is straightforward to confirm with standard tools that N is composite (fails primality check). Factoring 
# a 2048-bit (600-some-digit) N is a tall order but it is still worth a try... no cigar, though. So one 
# needs to be creative (investigative).
#
# There must be something mistake regarding phi. At least verify that the value would make sense for
# the naive solution, i.e., that integer p,q really exist such that phi = (p-1)*(q-1), N = p*q:
#
#   p + q = N - phi + 1   =>  q = N - phi + 1 - p = B - p,  so solve (B-p)*p = N for p => p^2 - B*p + N = 0

B = N - phi + 1
D = B*B - 4*N       # discriminant

(sqrtD, exact) = gmpy2.iroot(D, 2)  
if not exact:
   print("no integer p,q possible\n")
   exit(1)

sqrtD = int(sqrtD)    
p = (B - sqrtD) // 2  # needs accurate integer root
q = B - p

# So p,q do exist.. still, phi must be wrong since we cannot decrypt naively. Not all work is lost, however, 
# because now we have a (partial) factorization of N as p*q. Further factoring 300-some-digit p & q is MUCH easier 
# than factoring N directly, though still generally hard. One can try, nevertheless. E.g., within 5 minutes 
# with Yafu: p is (super likely) prime, while q = q1 * q2^2, where q1,q2 are (super likely) primes.
#

q1 = 114246317095974470506773678257568235122518242597047789547048839187083024865020001474658765781086764897848462941975998876745554658010228538590510838090170514826158000814626345298608897564379676590885135757454210473226786479123649044427073066377922690618563
q2 = 1157553415904668982313594731

#
# compute phi for N = p * q1 * q2^2 using Euler's formula, then obtain d and decrypt
#

phi = (p - 1) * (q1 - 1) * (q2 - 1) * q2    # Euler formula for p *q1 * q2^2
d = modinv(e, phi)


# read encryptions, decrypt data

for i in range(1226):
   fname = "secret" + ("000" + str(i))[-4:]
   with open(fname, "rb") as f:
      cmsg = f.read()
   c = int.from_bytes(cmsg, byteorder = 'big')
   m = pow(c, d, N)
   msg = m.to_bytes(256, byteorder = 'big').lstrip(b"\x00")  # strip leading zeroes
   sys.stdout.buffer.write(msg)

