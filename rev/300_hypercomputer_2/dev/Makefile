HDR:= turing2d.h tests.h
EXE:= hypercomputer2

#CFLAGS:= -O1 -Wall -fno-inline
CFLAGS:= -O2 -Wall -fno-inline


all: $(EXE)

clean:
	rm -f $(EXE)


$(EXE): $(HDR)



hypercomputer2: hypercomputer2.C
	g++ $(CFLAGS) -o $@ $<
	strip $@

%: %.C
	g++ $(CFLAGS) -o $@ $<


