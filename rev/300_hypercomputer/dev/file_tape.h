/*== file-based taped implementation  ==*/

#include <stdlib.h>


struct Tape {
   FILE* tape;
   char* fn;
   int pos; // real pos - 1
};

int realPos(int pos) { return pos + 1; }

void tapeReset(struct Tape* tp) {
   FILE* f = tp->tape;
   fseek(f, 1, SEEK_SET);
   tp->pos = 0;  
}

struct Tape createTape(int sz) {
   FILE* f = fopen("HTMP", "w+");
   for (int i = 0; i <= sz; i ++) fputc(0, f);
   fflush(f);
   struct Tape tpStruct;
   tpStruct.tape = f;
   tapeReset(&tpStruct);
   return tpStruct;
}

void tapeWrite(char s, struct Tape* tp) {  
   FILE* f = tp->tape;
   fputc(s, f);
   fflush(f);
   fseek(f, -1, SEEK_CUR);
}

char tapeRead(struct Tape* tp) { 
   FILE* f = tp->tape;
   char c = fgetc(f);
   fseek(f, -1, SEEK_CUR);
   return c;
}

void tapeLeft(struct Tape* tp) {
   FILE* f = tp->tape;
   fseek(f, -1, SEEK_CUR);
   tp->pos --;
}

void tapeRight(struct Tape* tp) {
   FILE* f = tp->tape;
   fseek(f, 1, SEEK_CUR);
   tp->pos ++;
}





void printTape(struct Tape* tp, int n) {
   FILE* f = tp->tape;
   fseek(f, 1, SEEK_SET);
   for (int i = 0; i < n; i ++) {   // print directly, without affecting position
      char s = fgetc(f);
      if (s == 0) printf("0");
      else if (s == 1) printf("1");
      else printf("x");
   }
   printf("\n");
}


// writes a nonnegative number at beginning of tape, terminates by single 0
void writeNum(int a, struct Tape* tp, int pos) {
   FILE* f = tp->tape;
   fseek(f, pos + 1, SEEK_SET);
   for (int i = 0; i < a; i ++) fputc(1, f);  // write direct
   fputc(0, f);
   fflush(f);
}

// read number from beginning of tape, until 0 separator
int readNum(struct Tape* tp) {
   FILE* f = tp->tape;
   fseek(f, 1, SEEK_SET);
   for (int i = 0; 1 == 1; i ++) {   // read directly
      if (fgetc(f) == 0) return i;
   }
   // control never reaches here
} 


/* EOF */
