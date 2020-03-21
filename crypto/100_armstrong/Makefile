all: build run

build: armstrong
	docker build . -t $<

run: armstrong
	docker run --name $< --restart always -itd -p 4001:4001 $<

kill: armstrong
	docker stop $<
	docker rm $<

.PHONY: armstrong