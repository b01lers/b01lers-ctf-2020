// in challenge mode, use dead code to get extra space in the symbol table


#include <stdio.h>
#include <sys/time.h>

#include "string_ops.h"

const unsigned char flag[] = {66, 228, 112, 148, 37, 210, 93, 175, 153, 86, 224, 129, 245, 28, 252, 81, 142, 120, 166, 166, 57, 107, 21, 145, 99, 28, 113, 1, 11, 225, 244, 228, 84, 149, 238, 135, 182, 222, 64, 53, 31, 91, 149, 114, 65, 134, 115, 151, 11, 172, 104, 146, 128, 84, 146, 137, 178, 14, 254, 0};

// dummy function 
// editing gettimeofday -> get/getchar later gives us 9/5 extra characters to play with
long int foo() {
   struct timeval t;
   gettimeofday(&t, 0);
   return t.tv_sec;
}


int main() {

   unsigned char buf[200];
   int i;

   srand(20200315);

   buf[0] = 0;
   strcat((char*) buf, (const char*) flag);
   for (i = 0; i < 1000; i ++) {
      int pos = (unsigned char) (rand() % strlen((const char*)flag));
      int shft = (unsigned char) (rand() % 255) + 1;
      swap(buf, pos);
      roll(buf, shft, strlen((const char*)flag) - pos);
   }
  
   printf("%s", buf);

   return 0;
}

//EOF
