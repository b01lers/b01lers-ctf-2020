%option noyywrap

%{
	#include <cstdio>
	#include <cstdint>
	#include <cstdlib>
	#include <iostream>
	#include <string>

	#include "register.hpp"
	#include "instruction.hpp"
	#include "context.hpp"
	#include "trinterpreter.hpp"
	#include "trinterpreter.tab.h"
%}

/* Literals */
SEMICOL ";"

/* Regexes */
REG r(a|b|c|d|e)
IMM #0[Xx][a-fA-F0-9]{1,16}
WS [ \r\n\t]*
COM \/[\/]+.*

%%

{WS}			{ 								} /* Skip over whitespace */
{COM} 			{ 								} /* Skip over comments */
"mpc"			{ return TOKEN_MPC;				} /* Make Program Counter */
"hcf"			{ return TOKEN_HCF;				} /* Halt & Catch Fire */
"enq"			{ return TOKEN_ENQ;				} /* Enqueue 	 */
"deq"			{ return TOKEN_DEQ;				} /* Dequeue 	 */
"jsz"			{ return TOKEN_JSZ;				} /* Jump Same Zeroes */
"allrmprcivri" 	{ return TOKEN_ALLRMPRCIVRI; 	} /* Assign LL Reg Make PC Invert RI */
"mooq" 			{ return TOKEN_MOOQ; 			} /* Middle Out Order Queue */
"rv" 			{ return TOKEN_RV; 				} /* Rotate Vertical */
"lar" 			{ return TOKEN_LAR; 			} /* Load and Reorder */
"aml" 			{ return TOKEN_AML; 			} /* Add marklist */
"gml" 			{ return TOKEN_GML; 			} /* Go marklist */
"sq" 			{ return TOKEN_SQ; 				} /* Switch queues */
"emp" 			{ return TOKEN_EMP; 			} /* emplace reg into another reg */

";" 			{ return TOKEN_SEMICOL; 		} /* Literal Semicolon */


{REG} 			{ yylval.ident = strdup(yytext); return TOKEN_REG; 			} /* Register */

{IMM} 			{ yylval.ival = new int64_t; *yylval.ival = std::strtol(yytext + 1, NULL, 16); 
				  return TOKEN_IMM; 	} /* Immediate */

%%
