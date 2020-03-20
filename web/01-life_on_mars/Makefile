all: build
run: start wait exec
debug: start_debug shell

PORT_PREFIX = 10

# Also the challenge number
PORT_POSTFIX = 01
NAME = life_on_mars
FNAME = $(PORT_POSTFIX)-$(NAME)-build-and-run
SQLOPTS = -e MYSQL_ROOT_PASSWORD=toor -e MYSQL_DATABASE=aliens

build:
	docker build -t $(FNAME) .

start:
	docker run --rm -itd --name $(FNAME) -p $(PORT_PREFIX)$(PORT_POSTFIX):5000 $(SQLOPTS) $(FNAME)

start_debug:
	docker run --rm -itd --name $(FNAME) --entrypoint=/bin/bash -p $(PORT_PREFIX)$(PORT_POSTFIX):5000 $(SQLOPTS) $(FNAME)

wait:
	sleep 30

exec:
	docker exec -itd $(FNAME) /entrypoint.sh

shell:
	docker exec -it $(FNAME) /bin/sh

stop:
	docker kill $(FNAME)
