cc=gcc

meshuggah: meshuggah.c
	$(cc) meshuggah.c	-z execstack -o meshuggah

.PHONY: clean
	rm meshuggah
