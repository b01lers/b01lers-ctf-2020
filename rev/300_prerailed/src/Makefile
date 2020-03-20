SRCFILES=instruction.cpp register.cpp context.cpp trinterpreter.cpp
PSRCFILES=preprocessor.cpp
CFLAGS=-std=c++17
DFLAGS=-g
OFLAGS=-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all -fstack-clash-protection -z relro -z now -z noexecstack  -fcf-protection=full
CC=g++

all: prerailed

preprocessor.tab.c preprocessor.tab.h: preprocessor.y
	bison -d $<

lex.yy.c: preprocessor.l preprocessor.tab.h
	flex -v $<

prerailed: $(PSRCFILES) lex.yy.c preprocessor.tab.c preprocessor.tab.h
	$(CC) -o $@ $^ $(CFLAGS) $(OFLAGS)

clean: 
	rm preprocessor preprocessor.tab.h lex.yy.c preprocessor.tab.h
