/*== hybrid functions ==*/
 
#ifndef FAST            // Turing machine by default
#  include "./turing.h"    
#else                   // fast basic algs otherwise

int add(int a, int b, struct Tape* tp) {  return a + b; }
int sub(int a, int b, struct Tape* tp) {  return a - b; } // assumes a >= b
int sub0(int a, int b, struct Tape* tp) {  return (a >= b) ? a - b : 0; }
int mod2(int a, struct Tape* tp) { return a & 1; }
int div2(int a, struct Tape* tp) { return a >> 1; }
int mul2(int a, struct Tape* tp) { return a << 1; }
int nonzero(int a, struct Tape* tp) { return (a != 0) ? 1 : 0; }

int cmp(int a, int b, struct Tape* tp) {
   if (a == b) return 0;
   if (a > b) return 1;
   return 2;
}

int sum(int n, int* vals, struct Tape* tp) {
   int s = 0;
   for (int i = 0; i < n; i ++) s += vals[i];
   return s;
}

#endif  /* FAST */


// hybrid algorithms


int bitflip(int a, struct Tape* tp) {       // O(a^2 ln a)
   int res = 0, base = 1;
   while (nonzero(a, tp)) {
      if (mod2(a, tp) == 0) res = add(res, base, tp);
      a = div2(a, tp);
      base = add(base, base, tp);
   }
   return res;
}


int sumInt(int nmax, struct Tape* tp) {   // O(nmax^3)
   int sum = 0;
   for (int n = 0; n <= nmax; n ++) sum = add(sum, n, tp);
   return sum;
}


// naive mod (repeatedly subtracts n): O(a^3 / n) 
int modSTD(int a, int n, struct Tape* tp) {  
   int res2;
   while (1) {
     res2 = sub0(a, n, tp);
     if (nonzero(res2, tp) == 0) break;
     a = res2;
   }
   if (cmp(a, n, tp) == 0) return 0;
   return a;
}


// my most efficient (a mod n) code: O(a^2 * ln(a/n)) 
int modFAST2(int a, int n, struct Tape* tp) {
   // break it into a = 2^i * d + rtot form, where d <= n
   int d = a;
   int rtot = 0;
   int rbase = 1;
   int  i;
   for (i = 0; 1; i ++) {
      if (sub0(d, n, tp) == 0) break;   // quit if d <= n
      if (mod2(d, tp) != 0) rtot = add(rtot, rbase, tp);
      d = div2(d, tp);
      rbase = mul2(rbase, tp);
   }
   // reconstruct (2^i * d) mod n iteratively
   int res = d;
   for (; i > 0; i --) {
      res = mul2(res, tp);
      int res2 = sub0(res, n, tp);
      if (nonzero(res2, tp)) res = res2;
   }
   // add remainder and use standard alg to get (2^i * d + rtot) mod n
   res = add(res, rtot, tp);
   return modSTD(res, n, tp);   
}


int mod(int a, int n, struct Tape* tp) {   return modFAST2(a, n, tp);  }


/* EOF */
