CC=g++
CFLAGS=-O3 -s -D_FORTIFY_SOURCE=2 -fstack-protector-all -fstack-clash-protection -z relro -z now -z noexecstack  -fcf-protection=full

all: engine

engine: engine.cpp
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm engine