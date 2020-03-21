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

#include "instruction.hpp"
#include "register.hpp"
#include "context.hpp"

extern int yydebug;
extern FILE * yyin;

int yyparse(void);
int yyerror(const char * s);

extern Context * ctx;
extern uint64_t * linenum;
