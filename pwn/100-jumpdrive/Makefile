all: jumpdrive

jumpdrive: jumpdrive.c
	gcc -o jumpdrive jumpdrive.c  

build:
	docker build . -t jumpdrive

run:
	docker run --name jumpdrive --restart always -itd -p 1337:1337 jumpdrive

clean:
	rm -f jumpdrive

.PHONY: build
.PHONY: run
.PHONY: clean
