xwing: xwing.c memdump.c
	gcc xwing.c memdump.c -o xwing -Wl,--section-start=.init=0x258a3b90,--section-start=.bss=0x131ecd10,--section-start=.data=0x130bcd10,-z,relro,-z,now -no-pie
