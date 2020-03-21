/*== minimal Turing machine programs (only use 0 & 1, no blanks etc)  

     implemented codes:

       add      a+b:          O(N)
       sub      a-b:          O(N^2)   - requires a >= b
       sub0     max(a-b,0):   O(N^2)
       cmp      cmp(a,b):     O(N^2)
       mod2     a mod 2:      O(a)
       div2     a/2:          O(a^2)
       mul2     a*2:          O(a^2)
       sum      sum_k(a_k):   O(k^2 N)
       nonzero  a!=0:         O(1)

==*/

#include <stdio.h>

//#define DBG_RUN 1
#define DBG_RUN 0


struct Move {
   int state;       // 0- n
   char symbol;      // 0 or 1
   int direction;   // +-1
};

struct CodeLine {
   struct Move m0, m1; // move on symbol = 0, move on symbol = 1
};

void printMove(const struct Move m, int q, int s) {
   printf("%d(%d)->%d(%d),%s", q, s, m.state, m.symbol, (m.direction == 1) ? "R" : "L");
}

void printCode(const struct CodeLine* code) {
   for (int q = 0; 1 == 1; q ++) {
      printMove(code[q].m0, q, 0);
      printf("  ");
      printMove(code[q].m1, q, 1);
      printf("\n");
      if (code[q].m1.state < 0) return;
   }
}


void runCode(const struct CodeLine* code, struct Tape* tp) {
   tapeReset(tp);
   int q = 0;
   while (q >= 0) {
      if (DBG_RUN != 0) {
         printf("q=%d pos=%d ", q, tp->pos);
         printTape(tp, 100);
      }
      char s = tapeRead(tp);
      const struct Move m = (s == 0) ? code[q].m0 : code[q].m1;
      q = m.state;
      tapeWrite(m.symbol, tp);
      if (m.direction > 0) tapeRight(tp);
      else tapeLeft(tp);
   }
}


// code for a+b:  O(N),  fill in 0 between numbers, then erase last 1 of 2nd number
// somewhat shorter than actual Turing machine code because no need to return tape to beginning
const struct CodeLine addCode[] = {   
     { { 1,  1,  1},  { 0,  1,  1} },     // q0 - moving right find 0, then write 1 and switch to q1 
     { { 2,  0, -1},  { 1,  1,  1} },     // q1 - moving right find 0, then left and switch to q2
     { {-1,  0,  1},  {-1,  0,  1} }      // q2 - write 0, then right, and TERMINATE
};
   

int add(int a, int b, struct Tape* tp) {
   writeNum2(a, b, tp);
   runCode(addCode, tp);
   return readNum(tp);
}


// code for a-b (ASSUMES a >= b >= 0): O(N^2), graduallly move 1s from R end of 2nd number to R end of 1st number
const struct CodeLine subCode[] = {   
     { { 1,  0,  1},  { 0,  1,  1} },     // q0: move R past 1s, otherwise -> q1+R
     { { 2,  0, -1},  { 1,  1,  1} },     // q1: move R past 1s, otherwise -> q2+L
     { {-1,  0,  1},  { 3,  0, -1} },     // q2: if 0, TERMINATE +R, 1: erase->q3+L
     { { 7,  0, -1},  { 4,  1, -1} },     // q3: on 0: -> q7+L, on 1: q4+L
     { { 5,  0, -1},  { 4,  1, -1} },     // q4: move L past 1s, on 0: -> q5+L
     { { 5,  0, -1},  { 6,  0,  1} },     // q5: move L past 0s, on 1: -> erase p6+R
     { { 6,  0,  1},  { 1,  1,  1} },     // q5: move R past 0s, on 1: -> q1+R
     { { 7,  0, -1},  {-1,  0,  1} }      // q7: move past 0s, on 1: -> erase+TERMINATE
};

int sub(int a, int b, struct Tape* tp) {
   writeNum2(a, b, tp);
   runCode(subCode, tp);
   return readNum(tp);
}


// code for negative-protected sub(a,b) = max(a-b, 0):  O(N^2)   
// - FIXME: inelegant, but works
const struct CodeLine sub0Code[] = {
     { {10,  0,  1},  { 1,  1,  1} },     // q0: if 0: L->q10, 1: R->q1
     { { 2,  0, -1},  { 1,  1,  1} },     // q1: if 1: R->q1, 0: L->q2
     { { 3,  0,  1},  { 3,  0,  1} },     // q2: erase, R->q3
     { { 4,  1,  1},  { 4,  1,  1} },     // q3: write, R->q4
     { {11,  0, -1},  { 5,  1,  1} },     // q4: 0:, L->q11, if 1: R->q5
     { { 6,  0, -1},  { 5,  1,  1} },     // q5: if 1: R->q5, 0: L->q6
     { {-1,  0, -1},  { 7,  0, -1} },     // q6: if 0: (a>b) TERM, 1: erase,L->q7
     { {-1,  0, -1},  { 8,  0, -1} },     // q7: if 0: (a>b) TERM, 1: erase,L->q8
     { { 9,  0, -1},  { 8,  1, -1} },     // q8: if 1: L->q8, if 0: L->q9
     { { 0,  0,  1},  { 9,  1, -1} },     // q9: if 1: L->q9, if 0: R->q0
     { {-1,  0,  1},  {-1,  0,  1} },     //q10: if 0: a-b=0, TERMINATE, if 1: b>a, TERMINATE
     { {12,  0, -1},  {12,  0, -1} },     //q11: erase,L->q12
     { {-1,  1,  1},  {-1,  1,  1} }      //q12: write,TERMINATE
};

int sub0(int a, int b, struct Tape* tp) {
   writeNum2(a, b, tp);
   runCode(sub0Code, tp);
   return readNum(tp);
}



// code for cmp(a,b) = 0: if a == b, 1:  if a > b,  2: if a < b   - O(N^2)
// - FIXME: doubly inelegant (based on inelegant sub0), but works
const struct CodeLine cmpCode[] = {
     { {10,  0,  1},  { 1,  1,  1} },     // q0: if 0: L->q10, 1: R->q1   go past 1st number, catch 0 (q10)
     { { 2,  0, -1},  { 1,  1,  1} },     // q1: if 1: R->q1, 0: L->q2    
     { { 3,  0,  1},  { 3,  0,  1} },     // q2: erase, R->q3             move 1 from 1st to 2nd num, catch 2nd==0 (q11)
     { { 4,  1,  1},  { 4,  1,  1} },     // q3: write, R->q4             
     { {11,  0, -1},  { 5,  1,  1} },     // q4: 0:, L->q11, if 1: R->q5   
     { { 6,  0, -1},  { 5,  1,  1} },     // q5: if 1: R->q5, 0: L->q6
     { { 7,  0, -1},  { 7,  0, -1} },     // q6: erase,L->q7    erase '11' from end of 2nd number 
     { {-1,  0, -1},  { 8,  0, -1} },     // q7: if 0: (a>b) TERM, 1: erase,L->q8    catch insufficient '01' ending
     { { 9,  0, -1},  { 8,  1, -1} },     // q8: if 1: L->q8, if 0: L->q9
     { { 0,  0,  1},  { 9,  1, -1} },     // q9: if 1: L->q9, if 0: R->q0
     { {-1,  0,  1},  {16,  0, -1} },     //q10: if 0: TERMINATE(a==b), if 1: b>a, erase,L->q16
     { {12,  0, -1},  {12,  0, -1} },     //q11: erase,L->q12
     { {13,  0, -1},  {13,  0, -1} },     //q12: erase,L->q13
     { {14,  0,  1},  {13,  0, -1} },     //q13: if 1: erase,L->q13, 0: R->q14     back to beginning of 1st
     { {15,  1,  1},  {15,  1,  1} },     //q14: write,R->q15                      overwrite with '10'
     { {-1,  0,  1},  {-1,  0,  1} },     //q15: erase,TERMINATE(a>b)
     { {17,  1,  1},  {16,  0, -1} },     //q16: if 1: erase,L->q16TERMINATE(a==b), 0: write,R->q17
     { {18,  1,  1},  {18,  1,  1} },     //q17: write,R->q18
     { {-1,  0,  1},  {-1,  0,  1} }      //q18: erase,TERMINATE(a<b)
};

int cmp(int a, int b, struct Tape* tp) {
   writeNum2(a, b, tp);
   runCode(cmpCode, tp);
   return readNum(tp);
}


// code that computes a number mod 2: O(N), counts 1s then sets 0th position accordingly
const struct CodeLine mod2Code[] = {
   { { 2,  0, -1},  { 1,  1,  1} },                      // q0: moving R, q1 if 1, q2(EVEN)+L if 0
   { { 3,  0, -1},  { 0,  1,  1} },                      // q1: moving R, q0 if 1, q3(ODD)+L if 0
   { {-1,  0,  1},  { 2,  0, -1} },                      // q2: moving L fill with 0, then TERMINATE(EVEN)
   { { 4,  0,  1},  { 3,  0, -1} },                      // q3: moving L fill with 0, then q4 + R   
   { {-1,  1,  1},  {-1,  1,  1} }                       // q4: fill with 1 then TERMINATE(ODD)
};

int mod2(int a, struct Tape* tp) {
   writeNum(a, tp, 0);
   runCode(mod2Code, tp);
   return readNum(tp);
}


// divide by 2 (round down): O(N), basically converts 111111.. -> 010101.., then counts 1s
const struct CodeLine div2Code[] = {
   // q0-q2 step to end (00) and on way mark every odd 1 to 0
   // q3-q5 move 1 at right end to position of 0 in -0-1- gap, then turn back
   // q6-q7 move R to end of 1111, erase rightmost 1, then repeat from q4 
   { { 3,  0, -1},  { 1,  0,  1} },                      // q0: if 1: erase+R->q1, 0: L->q3 (land on *0/1*-0)
   { { 2,  0, -1},  { 0,  1,  1} },                      // q1: if 1: R->q0, 0: L->q2 (land on *0*-0)
   { { 3,  0, -1},  { 3,  0, -1} },                      // q2: L->q3 (end on *0/1*-0)
   { {-1,  0,  1},  { 4,  0, -1} },                      // q3: 0: TERMINATE (00), 1: ERASE+q4->L
   { { 5,  1, -1},  { 4,  1, -1} },                      // q4: if 1: L->q4 0: write 1,L->q5,
   { {-1,  0,  1},  { 6,  1,  1} },                      // q5: if 0: TERMINATE, 1: R->q6
   { { 7,  0, -1},  { 6,  1,  1} },                      // q6: if 1: R->q6, 0: L->q7
   { { 4,  0, -1},  { 4,  0, -1} }                       // q7: write 0,L->q4
};

int div2(int a, struct Tape* tp) {
   writeNum(a, tp, 0);
   runCode(div2Code, tp);
   return readNum(tp);
}


// multiply by 2 (round down): O(N^2), move number right after itself, then fill in leading zeroes
const struct CodeLine mul2Code[] = {
   // q0: test for 0
   // q1-q3: change terminator to 00
   { {-1,  0,  1},  { 1,  1,  1} },                      // q0: if 0: TERMINATE, 1: R->q1
   { { 2,  0,  1},  { 1,  1,  1} },                      // q1: if 1: R->q1, 0: R->q2
   { { 3,  0, -1},  { 3,  0, -1} },                      // q2: erase,L->q3
   { { 4,  0,  1},  { 4,  1,  1} },                      // q3: R->q4
   { { 5,  1,  1},  { 4,  1,  1} },                      // q4: if 1: R->q4, 0: write, R->q5
   { { 6,  0, -1},  { 6,  0, -1} },                      // q5: erase,L->q6    // keep writing terminator 0
   { { 7,  0, -1},  { 6,  1, -1} },                      // q6: if 1: L->q6, 0: L->q7
   { { 7,  0, -1},  { 8,  0, -1} },                      // q7: if 0: L->q7, 1: erase,L->q8
   { {10,  0,  1},  { 9,  1,  1} },                      // q8: if 1: R->q9, 0: R->q10
   { { 9,  0,  1},  { 4,  1,  1} },                      // q9: if 0: R->q9, 1: R->q4
   { {10,  1,  1},  {11,  1,  1} },                      //q10: if 0: write,R->q10, 1: R->q11
   { {12,  0, -1},  {11,  1,  1} },                      //q11: if 1: R->q11, 0: L->q12
   { {-1,  0,  1},  {-1,  0,  1} }                       //q12: erase,TERMINATE
};

int mul2(int a, struct Tape* tp) {
   writeNum(a, tp, 0);
   runCode(mul2Code, tp);
   return readNum(tp);
}


// returns sum of all numbers  given in format 0 a 0 b 0 c 0 ... z 0 0:     O(k^2*N)
// where all numbers are nonzero and are coded the usual way (unary)
// (any zero number effectively terminates sequence)
const struct CodeLine sumCode[] = {
   // move right until 00
   // q3-q5 move 1 at right end to 0 in -0-1- gap, then turn back
   // q6-q7 move R to end of 1111, erase rightmost 1, then repeat from q4 
   { { 1,  0,  1},  { 0,  1,  1} },                      // q0: if 1: R->q0, if 0: R->q1
   { { 2,  0, -1},  { 0,  1,  1} },                      // q1: if 0: L->q2, if 1: R->q0
   { { 3,  0, -1},  { 3,  1, -1} },                      // q2: L->q3 (end on *0/1*-0)
   { {-1,  0,  1},  { 4,  0, -1} },                      // q3: 0: TERMINATE (00), 1: ERASE+q4->L
   { { 5,  1, -1},  { 4,  1, -1} },                      // q4: if 1: L->q4 0: write 1,L->q5,
   { {-1,  0,  1},  { 6,  1,  1} },                      // q5: if 0: TERMINATE, 1: R->q6
   { { 7,  0, -1},  { 6,  1,  1} },                      // q6: if 1: R->q6, 0: L->q7
   { { 4,  0, -1},  { 4,  0, -1} }                       // q7: write 0,L->q4
};

int sum(int n, int* values, struct Tape* tp) {
   writeNumN(n, values, tp);
   runCode(sumCode, tp);
   return readNum(tp);
}



// returns 1 if the number is nonzero, 0 otherwise: O(1), just check first position
const struct CodeLine nonzeroCode[] = {
   { {-1,  0,  1},  { 1,  1,  1} },                      // q0: 0: TERMINATE(0), 1:->q2(R)
   { {-1,  0,  1},  {-1,  0,  1} }                       // q2: erase, TERMINATE(0)
};


int nonzero(int a, struct Tape* tp) {
   writeNum(a, tp, 0);
   runCode(nonzeroCode, tp);
   return readNum(tp);
}


/* EOF */
