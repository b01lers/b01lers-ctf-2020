#include <stdio.h>

typedef unsigned long long int u64;

//#define SLOW

# ifdef SLOW
u64 f(u64 a, u64 b) {
   u64 ret = 1;
   for (u64 i = 0; i < b; i ++) ret *= a;
   return ret;
}
#else
u64 f(u64 a, u64 b) {
   u64 tmp = a;
   u64 ret = 1;
   while (b > 0) {
      if ((b & 1) != 0) ret *= tmp;
      b >>= 1;
      tmp *= tmp;
   }
   return ret;
}
#endif



int main() {
   const unsigned char pad[52]  = { 
      51, 194, 223, 154, 39, 142, 239, 209, 86, 10, 159, 52, 145, 109, 33, 250, 20, 202, 210, 33, 153, 240, 42, 
     199, 85, 144, 237, 97, 142, 140, 47, 113, 94, 234, 85, 133, 129, 107, 17, 38, 18, 215, 116, 191, 109, 142, 
      53, 182, 217, 57, 204, 84
   };
   u64 a = 113,  b = 3;
   for (int i = 0; i < 52; i ++) {
      u64 x = f(a, b);
      u64 y = 0, z = x;
      for (int j = 0; j < 8; j ++) {
         y ^= z & 0xff;
         z >>= 8;
      }
      putc(pad[i] ^ y, stdout);
      fflush(stdout);
      b = a;
      a = x;
   }
   return 0;
}
