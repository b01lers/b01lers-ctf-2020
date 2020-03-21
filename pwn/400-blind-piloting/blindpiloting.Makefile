blindpiloting: blindpiloting.c
	gcc -o $@ $<
	rm $<
	rm Makefile
