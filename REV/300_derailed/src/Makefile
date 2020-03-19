CC=gcc
GCFLAGS=$(shell pkg-config --cflags gtk+-3.0)
GLDFLAGS=$(shell pkg-config --libs gtk+-3.0)
CFLAGS=-rdynamic -std=gnu11 
WFLAGS=-Wall -Wextra -Werror

all: rr_crossing runner

rr_crossing: rr_crossing.c
	$(CC) $(CFLAGS) $(GCFLAGS) -o $@ $^ $(GLDFLAGS)

runner: rr_runner.c
	$(CC) -o $@ $< -ludis86

clean:
	rm rr_crossing

.PHONY: clean