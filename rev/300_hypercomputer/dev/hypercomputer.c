#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

//#define FAST

#include "./tape.h"
#include "./hybrid.h"
#include "./tests.h"



// allocate tape
const int TAPESIZE = 10000000;
struct Tape tpStruct;
struct Tape* tp = &tpStruct;


// coordinate functions

int fsum(int a, int b, struct Tape* tp) { // O(N^2)
   int vals[16];
   for (int i = 0; i < 16; i ++) {
      if (mod2(b, tp) == 0) vals[i] = a;
      else vals[i] = b;
      b = div2(b, tp);
   }
   return sum(16, vals, tp);
}


int gmod(int a, int b, struct Tape* tp) {  // O(N^2 ln N)
   int ra = mod(a, 2020, tp);
   int rb = mod(b, 2020, tp);
   return (cmp(ra + rb, 1010, tp) == 1) ? add(div2(a, tp), b, tp) : add(div2(b, tp), a, tp);
}




// char-by-char printing
void show(int t, const char* s) {
#ifndef FAST
   sleep(t);
#endif
   for (int i = 0; s[i] != 0; i ++) {
      printf("%c", s[i]);
      fflush(stdout);
#ifndef FAST
      usleep(10000);
#endif
   }
}



//=== MAIN ==
#ifndef CONFIG_DELAY
int main() {
#else
int main(const int argc, const char** const argv) {
#endif

   // create tape
   tpStruct = createTape(TAPESIZE);

   // tests
   //printCode(addCode);
   //TESTall(tp);
   //return 1;

   // initialize by current time (usec precision)
   struct timeval tv0;
   gettimeofday(&tv0, 0);
   srand(tv0.tv_usec * 1000000 + tv0.tv_sec % 1000000);
   int rval = rand();
   int freqi = (rval & 0xffff) + 0x10000;   //   [1-2] * 65536
   int memi = (rval >> 16) + 0x8000;        // [0.5-1] * 65536
#ifdef HINTS
   printf("freq=%d,mem=%d\n", freqi, memi);
#endif
   double freq = 14. - 5. * freqi / 65535.;
   double mem =  64. - 50. * memi / 65535.;

   // header
   //printf("");
#ifdef FAST
   show(0, "\nFlight deck hypercomputer pc-TF2020 operational...");
#else
   show(0, "\nFlight deck hypercomputer pc-TF2020 *SIMULATOR* operational...");
#endif
   show(1, "\nQuantum clock: ");
   printf("%.7g", freq);
   show(0, " zetaHz, free membanks: ");
   printf("%.7g", mem);
   show(0, " kZB...");
   show(2, "\n\n**WARNING** Collision Imminent!! Evasive maneuver required.");
   show(2, "\n\nEnter target coordinates: ");   

   // read input
   unsigned int x, y;
   scanf("%d,%d", &x, &y);

   // verify that input came within 1 sec
   struct timeval tv1;
   gettimeofday(&tv1, 0);
   int dt = (tv1.tv_sec - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
#ifndef CONFIG_DELAY
   if (dt > 1000000) {
#else
   if (dt > ( (argc > 1) ? atoi(argv[1]) : 1000000) ) {
#endif
      show(1, "**OVERRIDE** Autopilot activated... setting course for 0,0");
      x = 0;
      y = 0;
   }

   // calculation
   show(0, "\nAnalyzing....");

   int x1 = fsum(freqi, memi, tp);
#ifdef HINTS
   printf("x1=%d, ", x1);
   fflush(stdout);
#endif
   int y1 = gmod(freqi, memi, tp);
#ifdef HINTS
   printf("y1=%d\n", y1);
#endif

   // decode input - DISABLE FOR VERSION 3
   // x = bitflip(x, tp);
   // y = bitflip(y, tp);
   //printf("x=%d, y=%d\n", x, y);
   // test
   int success = 0;
   if (x == x1) {
      if (y == y1) success = 1;
      else success = -1; 
   }
   
   // write outcome
#ifdef FAST
   sleep(0.3);
#else
   sleep(3);
#endif
   switch(success) {
   case 1: {
      printf("Hyperspeed jump commencing...");
      sleep(2);
      printf("\n\nEscaped!!\n");
      FILE* f = fopen("flag.txt", "r");
      char buf[100];
      fgets(buf, 100, f);
      fclose(f);
      printf("%s", buf);
      fflush(stdout);
      break;
   }
   case 0: {
      show(0, "Inconsistent coordinates...\n");
      show(2, "\n**FATAL IMPACT** No survivors.\n");
      break;
   }
   case -1: {
      show(0, "Hyperspeed jump in 2..");
      show(1, "1..");
      show(1, "\n\n**WORMHOLE** Stuck in infinite time loop.\n");
      break;
   }
   }//switch

   // for netcat
   fclose(stdout);
   fclose(stdin);
   //
   return 0;
}



//END
