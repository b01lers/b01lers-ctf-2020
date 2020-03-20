all: kobayashi

cc=gcc

kobayashi: kobayashi.c
	$(cc) kobayashi.c -no-pie -m32	-o kobayashi
	strip kobayashi
	#rm kobayashi.c
	#rm Makefile
