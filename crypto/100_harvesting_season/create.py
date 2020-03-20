def rollXor(s,key):
    o = ''
    for i in range(len(s)):
        o += chr(ord(s[i]) ^ key[i % len(key)])
    return o

if __name__ == "__main__":
    flag = "pctf{purdu3_stud3nts_f4v0r1t3_p4st_t1m3}"
    key = [0x69,0x42,0x01,0x23]
    enc = rollXor(flag,key).encode('hex')
    #print(enc)
    print("Encrypted: "+enc)
    #print("Decryped: "+rollXor(enc.decode('hex'),key))
