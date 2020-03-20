flag = "pctf{tr41ns_d0nt_h4v3_arms}"

p = ""
for i in range(len(flag)):
    if i & 1 is 1:
        p += chr(ord(flag[i])  ^ 42)
    else:
        p += flag[i]

print(p.encode('hex'))
