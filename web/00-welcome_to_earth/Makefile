all: build
run: start

PORT_PREFIX = 10

# Also the challenge number
PORT_POSTFIX = 00
NAME = welcome_to_earth
FNAME = $(PORT_POSTFIX)-$(NAME)-build-and-run

build:
	docker build -t $(FNAME) .

start:
	docker run --rm -itd --name $(FNAME) -p $(PORT_PREFIX)$(PORT_POSTFIX):5000 $(FNAME)

debug:
	docker run --rm -it --name $(FNAME) --entrypoint=/bin/bash -p $(PORT_PREFIX)$(PORT_POSTFIX):5000 $(FNAME)

shell:
	docker exec -it $(FNAME) /bin/sh

stop:
	docker kill $(FNAME)
