/*== memory-based tape implementation  ==*/

#include <stdlib.h>


struct Tape {
   char* tape;
   int pos;
};


struct Tape createTape(int sz) {
   char* t = malloc(sz + 1);
   t[0] = 0;
   t ++;
   struct Tape tp;
   tp.tape = t;
   tp.pos = 0;
   return tp;
}

void tapeWrite(char s, struct Tape* tp) {  tp->tape[tp->pos] = s; }

char tapeRead(struct Tape* tp) { return tp->tape[tp->pos]; }

void tapeLeft(struct Tape* tp) {   tp->pos --;  }

void tapeRight(struct Tape* tp) {   tp->pos ++;  }

void tapeReset(struct Tape* tp) {   tp->pos = 0;  }




void printTape(struct Tape* tp, int n) {
   for (int i = 0; i < n; i ++) {   // print directly, without affecting position
      char s = tp->tape[i];
      if (s == 0) printf("0");
      else if (s == 1) printf("1");
      else printf("x");
   }
   printf("\n");
}


// writes a nonnegative number at beginning of tape, terminates by single 0
void writeNum(int a, struct Tape* tp, int pos) {
   for (int i = 0; i < a; i ++) tp->tape[pos + i] = 1;  // prepare directl
   tp->tape[pos + a] = 0;
}

// read number from beginning of tape, until 0 separator
int readNum(struct Tape* tp) {
   for (int i = 0; 1 == 1; i ++) {   // read directly
      if (tp->tape[i] == 0) return i;
   }
   // control never reaches here
} 


/* EOF */
