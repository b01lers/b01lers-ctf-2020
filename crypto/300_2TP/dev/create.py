from Crypto import Random


def encrypt(m, pad):
   ret = bytearray()
   for c,p in zip(m, pad):
      ret.append(c ^ p)
   return ret


pad = Random.get_random_bytes(1000)

with open("msg1.txt", "rb") as f:
   msg1 = f.read()

with open("msg2.txt", "rb") as f:
   msg2 = f.read()

# remove trailing newlines (crude but works)
msg1 = msg1.strip()
msg2 = msg2.strip()

ctxt1 = encrypt(msg1, pad)
ctxt2 = encrypt(msg2, pad)

n = min(len(ctxt1), len(ctxt2))

with open("msg1.enc", "wb") as f:
   f.write(ctxt1[:n])

with open("msg2.enc", "wb") as f:
   f.write(ctxt2[:n])

