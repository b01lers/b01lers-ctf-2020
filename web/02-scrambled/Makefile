all: build
run: start
debug: start_debug shell

PORT_PREFIX = 10

# Also the challenge number
PORT_POSTFIX = 02
NAME = scrambled
FNAME = $(PORT_POSTFIX)-$(NAME)-build-and-run

build:
	docker build -t $(FNAME) .

start:
	docker run --rm -itd --name $(FNAME) -p $(PORT_PREFIX)$(PORT_POSTFIX):5000 $(FNAME)

start_debug:
	docker run --rm -itd --name $(FNAME) --entrypoint=/bin/bash -p $(PORT_PREFIX)$(PORT_POSTFIX):5000 $(FNAME)

shell:
	docker exec -it $(FNAME) /bin/sh

stop:
	docker kill $(FNAME)
