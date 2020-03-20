fp = open('./ciphertext.txt','r')
fp = fp.readline().decode('hex')

known = 'pctf'
k = ''
for i in range(len(known)):
    k += chr(ord(fp[i]) ^ ord(known[i % len(known)]))

p = ''
for i in range(len(fp)): 
    p += chr(ord(fp[i]) ^ ord(k[i % len(k)]))
print(p)
