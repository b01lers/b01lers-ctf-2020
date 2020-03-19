#gdb ,-q ,-x ,solve.py


arr1 = [17 ,8 ,28 ,4 ,58 ,50 ,101 ,51 ,122 ,56 ,50 ,114 ,37, 127]
arr2 = [34 ,59 ,56 ,111 ,50 ,52 ,49 ,42 ,126 ,101 ,100 ,108 ,50]
arr3 = [58 ,113 ,62 ,121 ,38 ,108 ,35 ,97 ,108 ,41 ,110 ,63]
key = "AKHBAAR"
for i in range(0, len(arr1)):
    index = i % len(key)
    flag_num = ord(key[index])
    ctext_num = arr1[i]
    print(str(chr(ctext_num ^ flag_num)), end='')

for i in range(0, len(arr2)):
    index = i % len(key)
    flag_num = ord(key[index])
    ctext_num = arr2[i]
    print(str(chr(ctext_num ^ flag_num)), end='')

for i in range(0, len(arr3)):
    index = i % len(key)-1
    flag_num = ord(key[index])
    ctext_num = arr3[i]
    print(str(chr(ctext_num ^ flag_num)), end='')
print('\n')
	

