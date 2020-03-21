/*== tape implementation ==*/


//#define MEM_TAPE

#ifdef MEM_TAPE
#  include "mem_tape.h"
#else
#  include "file_tape.h"
#endif


// writes two nonnegative numbers at beginning of tape, separated by 0, terminated by 0
void writeNum2(int a, int b, struct Tape* tp) {
   writeNum(a, tp, 0);
   writeNum(b, tp, a + 1);
}

// writes N positive numbers at beginning of tape, starting with 0, separated by 0, ending with 00
// any zero number effectively terminates sequence
void writeNumN(int n, int* values, struct Tape* tp) {
   int pos = 0;
   writeNum(0, tp, pos);
   pos ++;
   for (int i = 0; i < n; i ++) {
      int v = values[i];
      writeNum(values[i], tp, pos);
      pos += v + 1;
   }
   writeNum(0, tp, pos);
}


/* EOF */
