# incorrect/naive decoder
#

N = 22518213392401264818411278544481843914232432830458541414885458377878266793498750772354592395933629538430168704357367677366063506437840746114109698561818213653155337516332045907584538560207347457518815750143165409925001430273241092541136748646685328169745125245340633556971837060802857356695229674488893860374426117801802327059524160107136439418599365088385458686062313445632037797173490869675537943240896233769936787893899596578453468394750636934950285496609730610849908463004889068961426952923099134018106324063391090991215384284497435868352255958362702412123106399579166856780539143530223177815706341761329346665123
phi = 22518213392401264818411278544481843914232432830458541414885458377878266793498750772354592395933629538430168704357367677366063506437840746114109698561818213653155337516332045907584538560207347457518815750143165409925001430273241092541136748646685328169745125245340633556971837060802857356695229674488893860374125936771634231083724519781739692120840798867536892089959731316847037589936959996408416801992484839541189805041461052140389233753983174954128996839480404891785287303195083960639773803194332300000270420399549292186960561461628916388255677931409154971065184660947084539883190976066572465271852306890113256664720
e = 65537



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



# compute d from phi and e (assumes phi is correct!)

d = modinv(e, phi)


# read encryptions, decrypt data

for i in range(1226):
   fname = "secret" + ("000" + str(i))[-4:]
   with open(fname, "rb") as f:
      cmsg = f.read()
   c = int.from_bytes(cmsg, byteorder = 'big')
   m = pow(c, d, N)
   msg = m.to_bytes(256, byteorder = 'big').lstrip(b"\x00")  # strip leading zeroes
   print(i, msg)

