CC=gcc
AFLAGS=-masm=intel
CFLAGS=-no-pie 
OFLAGS=-s -fvisibility=hidden

all: spirit_tracks

spirit_tracks: spirit_tracks.c hash.s shadow.s
	$(CC) -o $@ $^ $(AFLAGS) $(CFLAGS) $(OFLAGS)

clean: spirit_tracks
	rm $^