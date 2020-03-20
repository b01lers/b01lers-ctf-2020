/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YY_TRINTERPRETER_TAB_H_INCLUDED
# define YY_YY_TRINTERPRETER_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 1 "trinterpreter.y" /* yacc.c:1909  */

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

#line 60 "trinterpreter.tab.h" /* yacc.c:1909  */

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    TOKEN_MPC = 258,
    TOKEN_HCF = 259,
    TOKEN_ENQ = 260,
    TOKEN_DEQ = 261,
    TOKEN_JSZ = 262,
    TOKEN_ALLRMPRCIVRI = 263,
    TOKEN_MOOQ = 264,
    TOKEN_RV = 265,
    TOKEN_LAR = 266,
    TOKEN_AML = 267,
    TOKEN_GML = 268,
    TOKEN_SQ = 269,
    TOKEN_EMP = 270,
    TOKEN_SEMICOL = 271,
    TOKEN_IMM = 272,
    TOKEN_REG = 273
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 17 "trinterpreter.y" /* yacc.c:1909  */

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

#line 111 "trinterpreter.tab.h" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_TRINTERPRETER_TAB_H_INCLUDED  */
