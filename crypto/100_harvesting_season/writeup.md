Author: A0su
Category: Crypto
Points: 100

# Multibyte Rolling XOR Challenge
Examining the image's metadata we find for the artist field a string of hex.

If we take this string and attempt a rolling XOR based on the known flag format: "pctf{" we can determine the key, of length 4.

```python
s = "1921754512366910363569105a73727c592c5e5701715e571b76304d3625317c1b72744d0d1d354d0d1d73131c2c655e".decode('hex')

prefix = 'pctf'

o=''
for i in range(len(prefix)):
  o += chr(ord(s[i]) ^ ord(prefix[i]))

print('key:', o)

p=''
for i in range(len(s)):
  p += chr(ord(s[i]) ^ ord(o[i%len(o)]))
print(p)
```

The following will obtain the key and then use that key to determine the flag.
