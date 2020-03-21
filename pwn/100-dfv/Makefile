all: dfv

dfv: dfv.c
	gcc dfv.c -o dfv -g
	strip dfv

build:
	docker build . -t dfv

run:
	docker run --name dfv --restart always -itd -p 13300:1337 dfv

clean:
	rm -f dfv

.PHONY: build
.PHONY: run
.PHONY: clean
