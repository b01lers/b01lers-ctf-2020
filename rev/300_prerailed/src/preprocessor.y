%code requires {
	#include <cstdio>
	#include <cstdlib>
	#include <cstdint>
	#include "preprocessor.hpp"
	#include <iomanip>

	extern int yylex(void);
	extern int yyparse();
	extern int yyerror(const char * s);
	extern FILE * yyin;
}

%union {
	int64_t ival;
	char * ident;
	struct instr * ins;
	int64_t val;

}

%token TOKEN_MPC TOKEN_HCF TOKEN_ENQ TOKEN_DEQ TOKEN_JSZ TOKEN_ALLRMPRCIVRI
%token TOKEN_MOOQ TOKEN_RV TOKEN_LAR TOKEN_AML TOKEN_GML TOKEN_SQ TOKEN_EMP
%token TOKEN_SEMICOL

%token<ival> TOKEN_IMM
%token<ident> TOKEN_REG

%type <ins> instruction
%type <ins> mpc hcf enq deq jsz allrmprcivri mooq rv lar aml gml sq emp
%type <val> register


%%

program:
	| program instruction TOKEN_SEMICOL {
		int64_t op = $2->op;
		int64_t sz = $2->size;
		int64_t * vals = $2->vals;
		out->write(reinterpret_cast<char*>(&op), sizeof(op));
		//std::cout << "OP: " << std::hex << op << std::endl;
		for (int64_t i = 0; i < sz; i++) {
			out->write(reinterpret_cast<char*>(&vals[i]), sizeof(vals[i]));
			//std::cout << "VAL: " << std::hex << vals[i] << std::endl;
		}
	}
	;

instruction
	: mpc {
		$$ = $1;	
	}
	| hcf {
		$$ = $1;
	}
	| enq {
		$$ = $1;
	}
	| deq {
		$$ = $1;
	}
	| jsz {
		$$ = $1;
	}
	| allrmprcivri {
		$$ = $1;
	}
	| mooq {
		$$ = $1;
	}
	| rv {
		$$ = $1;
	}
	| lar {
		$$ = $1;
	}
	| aml {
		$$ = $1;
	}
	| gml {
		$$ = $1;
	}
	| sq {
		$$ = $1;
	}
	| emp {
		$$ = $1;
	}
	;

mpc
	: TOKEN_MPC register TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[2];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->size = 2;
		$$->op = 0x7c;
	}
	| TOKEN_MPC register {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x7d;
	}
	;

hcf
	: TOKEN_HCF register register {
		$$ = new instr;
		$$->vals = new int64_t[2];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->size = 2;
		$$->op = 0x7e;
	}
	;

enq
	: TOKEN_ENQ register {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x7f;
	}
	| TOKEN_ENQ register TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[2];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->size = 2;
		$$->op = 0x80;
	}
	;

deq
	: TOKEN_DEQ register TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[2];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->size = 2;
		$$->op = 0x81;
	}
	| TOKEN_DEQ register {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x82;
	}
	| TOKEN_DEQ {
		$$ = new instr;
		$$->vals = NULL;
		$$->size = 0;
		$$->op = 0x83;
	}
	;

jsz
	: TOKEN_JSZ register register register {
		$$ = new instr;
		$$->vals = new int64_t[3];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->vals[2] = $4;
		$$->size = 3;
		$$->op = 0x84;
	}
	;

allrmprcivri
	: TOKEN_ALLRMPRCIVRI register TOKEN_IMM TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[3];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->vals[2] = $4;
		$$->size = 3;
		$$->op = 0x85;
	}
	| TOKEN_ALLRMPRCIVRI register register register {
		$$ = new instr;
		$$->vals = new int64_t[3];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->vals[2] = $4;
		$$->size = 3;
		$$->op = 0x86;
	}
	;

mooq
	: TOKEN_MOOQ {
		$$ = new instr;
		$$->vals = NULL;
		$$->size = 0;
		$$->op = 0x87;
	}
	;

rv
	: TOKEN_RV register register {
		$$ = new instr;
		$$->vals = new int64_t[2];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->size = 2;
		$$->op = 0x88;
	}
	| TOKEN_RV register register TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[3];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->vals[2] = $4;
		$$->size = 3;
		$$->op = 0x89;
	}
	;

lar
	: TOKEN_LAR register TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[2];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->size = 2;
		$$->op = 0x8a;
	}
	;

aml
	: TOKEN_AML {
		$$ = new instr;
		$$->vals = NULL;
		$$->size = 0;
		$$->op = 0x8b;
	}
	| TOKEN_AML register {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x8c;
	}
	| TOKEN_AML TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x8d;
	}
	;

gml
	: TOKEN_GML register {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x8e;
	}
	| TOKEN_GML TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x8f;
	}
	;

sq
	: TOKEN_SQ TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x90;
		
	}
	| TOKEN_SQ register {
		$$ = new instr;
		$$->vals = new int64_t[1];
		$$->vals[0] = $2;
		$$->size = 1;
		$$->op = 0x91;
	}
	;

emp
	: TOKEN_EMP register register TOKEN_IMM {
		$$ = new instr;
		$$->vals = new int64_t[3];
		$$->vals[0] = $2;
		$$->vals[1] = $3;
		$$->vals[2] = $4;
		$$->size = 3;
		$$->op = 0x92;
	}
	;

register
	: TOKEN_REG {
		if (strcmp($1, "ra") == 0) {
			$$ = int64_t(0x10);
		} else if (strcmp($1, "rb") == 0) {
			$$ = int64_t(0x11);
		} else if (strcmp($1, "rc") == 0) {
			$$ = int64_t(0x12);
		} else if (strcmp($1, "rd") == 0) {
			$$ = int64_t(0x13);
		} else if (strcmp($1, "re") == 0) {
			$$ = int64_t(0x14);
		}
	}
	;

%%

#include <cstdio>
#include "preprocessor.tab.h"

int yyerror(const char * s) {
	printf("*** Lexical error %s\n", s);
	exit(1);
}