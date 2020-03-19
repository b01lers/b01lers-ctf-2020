#include <string>
#include <vector>
#include <iostream>
#include <regex>
#include <fstream>
#include <queue>
#include <vector>
#include <vector>
#include <string>
#include <iostream>
#include <bitset>

extern int yydebug;
extern FILE * yyin;

int yyparse(void);
int yyerror(const char * s);

extern std::ofstream * out;

#ifndef INSTR
#define INSTR
typedef struct instr {
	int64_t size;
	int64_t op;
	int64_t * vals;
} instr;
#endif