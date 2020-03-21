// create starting data for challenge binary
// (applies operations to flag in reverse)

#include <stdio.h>
#include <stdlib.h>

#include "string_ops.h"

//#define IDENTITY_CHECK

const char* flag = "You did it!\nThe flag is: pctf{ELFs_can_h1de_many_s3Cr37s!}\n";


int main() {


   unsigned char buf[200];
   unsigned char swapVals[1000];
   unsigned char rollVals[1000];
   int i;

   srand(20200315);

   buf[0] = 0;
   strcat(buf, flag);
   for (i = 0; i < 1000; i ++) {
      swapVals[i] = (unsigned char) (rand() % strlen(flag));
      rollVals[i] = (unsigned char) (rand() % 255) + 1;
   }
   for (i = 999; i >= 0; i --) {
      int rs = swapVals[i];
      int rr = rollVals[i];
#ifdef IDENTITY_CHECK
      swap(buf, rs);
      roll(buf, rr, strlen(flag) - rs);
#endif
      roll(buf, -rr, strlen(flag) - rs);
      invswap(buf, rs);
      //printf("%d %d %d %s\n", rs, rr, strlen(buf), buf);
   }
  
   printf("%s", buf);
  
   // print initial data for C code
   printf("\nconst char flag[] = {");
   for (i = 0; i <= strlen(buf); i ++) printf("%d, ", buf[i]);
   printf("};\n");

   // ok
   return 0;
}

//EOF
