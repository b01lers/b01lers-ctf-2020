HDR:= hybrid.h file_tape.h mem_tape.h tape.h tests.h turing.h 
EXE:= hypercomputer-server hypercomputer-SIM

CFLAGS:= -O2

all: $(EXE)

clean:
	rm -f $(EXE)


$(EXE): $(HDR)



hypercomputer-server: hypercomputer.c
	gcc -DFAST -DMEM_TAPE -DCONFIG_DELAY $(CFLAGS) -o $@ $<

hypercomputer-SIM: hypercomputer.c
	gcc -DMEM_TAPE -O1 -o $@ $<
	strip -w -K tpStruct -K TESTall -K "_*" $@

%: %.c
	gcc $(CFLAGS) -o $@ $<


