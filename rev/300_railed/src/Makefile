SRCFILES=instruction.cpp register.cpp context.cpp trinterpreter.cpp
PSRCFILES=preprocessor.cpp
CFLAGS=-std=c++17
DFLAGS=-g -DDEBUG
OFLAGS=-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all -fstack-clash-protection -z relro -z now -z noexecstack  -fcf-protection=full
CC=g++

all: railed railed-debug

trinterpreter.tab.c trinterpreter.tab.h: trinterpreter.y
	bison -d $<

lex.yy.c: trinterpreter.l trinterpreter.tab.h
	flex $<


railed: $(SRCFILES) lex.yy.c trinterpreter.tab.c trinterpreter.tab.h 
	$(CC) -o $@ $^ $(CFLAGS) $(OFLAGS)

railed-debug: $(SRCFILES) lex.yy.c trinterpreter.tab.c trinterpreter.tab.h 
	$(CC) -o $@ $^ $(CFLAGS) $(OFLAGS) $(DFLAGS)

clean: 
	rm railed trinterpreter.tab.c lex.yy.c trintepreter.tab.h