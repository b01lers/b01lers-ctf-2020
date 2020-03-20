%code requires {
	#include <cstdio>
	#include <cstdlib>
	#include <cstdint>
	#include "instruction.hpp"
	#include "register.hpp"
	#include "context.hpp"
	#include "trinterpreter.hpp"

	extern int yylex(void);
	extern int yyparse();
	extern int yyerror(const char * s);
	extern FILE * yyin;
	extern uint64_t * linenum;
}

%union {
	int64_t * ival;
	Instruction * instr;
	Register * reg;
	char * ident;
	MPCInstruction * mpci;
	HCFInstruction * hcfi;
	ENQInstruction * enqi;
	DEQInstruction * deqi;
	JSZInstruction * jszi;
	ALLRMRPCIVRIInstruction * allrmprcivrii;
	MOOQInstruction * mooqi;
	RVInstruction * rvi;
	LARInstruction * lari;
	AMLInstruction * amli;
	GMLInstruction * gmli;
	SQInstruction * sqi;
	EMPInstruction * empi;
}

%token TOKEN_MPC TOKEN_HCF TOKEN_ENQ TOKEN_DEQ TOKEN_JSZ TOKEN_ALLRMPRCIVRI
%token TOKEN_MOOQ TOKEN_RV TOKEN_LAR TOKEN_AML TOKEN_GML TOKEN_SQ TOKEN_EMP
%token TOKEN_SEMICOL

%token<ival> TOKEN_IMM
%token<ident> TOKEN_REG

%type<instr> instruction;
%type<reg> register;
%type<mpci> mpc;
%type<hcfi> hcf;
%type<enqi> enq;
%type<deqi> deq;
%type<jszi> jsz;
%type<allrmprcivrii> allrmprcivri;
%type<mooqi> mooq;
%type<rvi> rv;
%type<lari> lar;
%type<amli> aml;
%type<gmli> gml;
%type<sqi> sq;
%type<empi> emp;

%%

program:
	| program instruction TOKEN_SEMICOL {
		*linenum = *linenum + 1;
	}
	;

instruction
	: mpc {
		ctx->add_instruction($1);
	}
	| hcf {
		ctx->add_instruction($1);
	}
	| enq {
		ctx->add_instruction($1);
	}
	| deq {
		ctx->add_instruction($1);
	}
	| jsz {
		ctx->add_instruction($1);
	}
	| allrmprcivri {
		ctx->add_instruction($1);
	}
	| mooq {
		ctx->add_instruction($1);
	}
	| rv {
		ctx->add_instruction($1);
	}
	| lar {
		ctx->add_instruction($1);
	}
	| aml {
		ctx->add_instruction($1);
	}
	| gml {
		ctx->add_instruction($1);
	}
	| sq {
		ctx->add_instruction($1);
	}
	| emp {
		ctx->add_instruction($1);
	}
	;

mpc
	: TOKEN_MPC register TOKEN_IMM {
		$$ = new MPCInstruction($3, $2);
	}
	| TOKEN_MPC register {
		$$ = new MPCInstruction(NULL, $2);
	}
	;

hcf
	: TOKEN_HCF register register {
		$$ = new HCFInstruction($2, $3);
	}
	;

enq
	: TOKEN_ENQ register {
		$$ = new ENQInstruction($2);
	}
	| TOKEN_ENQ register TOKEN_IMM {
		$$ = new ENQInstruction($3, $2);
	}
	;

deq
	: TOKEN_DEQ register TOKEN_IMM {
		$$ = new DEQInstruction($3, $2);
	}
	| TOKEN_DEQ register {
		$$ = new DEQInstruction($2);
	}
	| TOKEN_DEQ {
		$$ = new DEQInstruction();
	}
	;

jsz
	: TOKEN_JSZ register register register {
		$$ = new JSZInstruction($2, $3, $4);
	}
	;

allrmprcivri
	: TOKEN_ALLRMPRCIVRI register TOKEN_IMM TOKEN_IMM {
		$$ = new ALLRMRPCIVRIInstruction($3, $4, $2);
	}
	| TOKEN_ALLRMPRCIVRI register register register {
		$$ = new ALLRMRPCIVRIInstruction($2, $3, $4);
	}
	;

mooq
	: TOKEN_MOOQ {
		$$ = new MOOQInstruction();
	}
	;

rv
	: TOKEN_RV register register {
		$$ = new RVInstruction($2, $3);
	}
	| TOKEN_RV register register TOKEN_IMM {
		$$ = new RVInstruction ($4, $2, $3);
	}
	;

lar
	: TOKEN_LAR register TOKEN_IMM {
		$$ = new LARInstruction($3, $2);
	}
	;

aml
	: TOKEN_AML {
		$$ = new AMLInstruction();
	}
	| TOKEN_AML register {
		$$ = new AMLInstruction($2);
	}
	| TOKEN_AML TOKEN_IMM {
		$$ = new AMLInstruction($2);
	}
	;

gml
	: TOKEN_GML register {
		$$ = new GMLInstruction($2);
	}
	| TOKEN_GML TOKEN_IMM {
		$$ = new GMLInstruction($2);
	}
	;

sq
	: TOKEN_SQ TOKEN_IMM {
		$$ = new SQInstruction($2);
	}
	| TOKEN_SQ register {
		$$ = new SQInstruction($2);
	}
	;

emp
	: TOKEN_EMP register register TOKEN_IMM {
		$$ = new EMPInstruction($4, $2, $3);
	}
	;

register
	: TOKEN_REG {
		$$ = ctx->get_reg($1);
	}
	;

%%

#include <cstdio>
#include "trinterpreter.tab.h"

int yyerror(const char * s) {
	printf("*** Lexical error %s %ld\n", s, *linenum);
	exit(1);
}