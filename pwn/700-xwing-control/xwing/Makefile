all: xwing

xwing:
	docker build . -t $@
	docker run --name $@ --restart always -itd -p 1337:1337 $@
	docker cp $@:/home/$@/$@ ./$@.dist
	docker cp $@:/usr/lib/libc-2.30.so ./$@.libc
	chown ctf:ctf ./$@.dist
	chown ctf:ctf ./$@.libc

.PHONY: xwing
