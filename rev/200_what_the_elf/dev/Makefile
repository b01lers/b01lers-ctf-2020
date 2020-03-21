# must have movfuscator available (as movcc)

HDR:= string_ops.h
EXE:= whattheelf-normal whattheelf-create whattheelf

all: $(EXE)


$(EXE): $(OBJ)

clean:
	rm -f $(EXE)

whattheelf: whattheelf-normal
	python3 create.py whattheelf-normal whattheelf

whattheelf-normal: whattheelf.c $(HDR)
	movcc -s -o $@ -DNORMAL $<

whattheelf-create: whattheelf-create.c $(HDR)
	movcc -s -o $@ -DCREATE $<
