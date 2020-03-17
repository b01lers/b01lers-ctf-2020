all: build
run: start wait exec
debug: start shell

PORT_PREFIX = 10

# Also the challenge number
PORT_POSTFIX = 04
NAME = space_junk
FNAME = $(PORT_POSTFIX)-$(NAME)-build-and-run
SQLOPTS = -e MYSQL_ROOT_PASSWORD=toor -e MYSQL_DATABASE=moderators

build:
	docker build -t $(FNAME) .

start:
	docker run --rm -itd --name $(FNAME) -p $(PORT_PREFIX)$(PORT_POSTFIX):3000 $(SQLOPTS) $(FNAME)

wait:
	sleep 30

exec:
	docker exec -it $(FNAME) /entrypoint.sh

shell:
	docker exec -it $(FNAME) /bin/bash

stop:
	docker kill $(FNAME)
