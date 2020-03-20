all: build
run: start

PORT_PREFIX = 10

# Also the challenge number
PORT_POSTFIX = 05
NAME = alien_tech
FNAME = $(PORT_POSTFIX)-$(NAME)-build-and-run

compile: $(NAME)
$(NAME):
	emcc -o alien_tech.js alien_tech.c

compile_c:
	gcc -g -o alien_tech alien_tech.c

build:
	docker build -t $(FNAME) .

clean:
	rm -f $(NAME).js $(NAME).wasm $(NAME)

start:
	docker run --rm -itd --name $(FNAME) -p $(PORT_PREFIX)$(PORT_POSTFIX):3000 $(FNAME)

shell:
	docker exec -it $(FNAME) /bin/sh

stop:
	docker kill $(FNAME)
