/* 

   challenge based on 2D Turing machine 

*/

#include <fstream>
#include <cstdlib>
#include <unistd.h>
#include <sys/time.h>

#include "turing2d.h"
//#include "tests.h"




//=== MAIN ===

int main() {


   // read code
   std::cout << "\n[Enter code] ";
   std::string code;
   std::cin >> code;


   // set up TM
   Program prog(code);
   Tape2D tape(100, 20);

   //TEST7(tape);

   // verify code - challenge against 100 random evaluations
   struct timeval tv0;
   gettimeofday(&tv0, 0);
   srand(tv0.tv_usec * 1000000 + tv0.tv_sec % 1000000);

   for (int i = 0; i < 100; i ++) {
      int rval = rand();
      int v = (rval & 0xffff) + 0x10000;   //   [1-2] * 65536
      tape.writeNumber(v, 2);    // FIXME: should we keep erasing tape for simplicity?
      tape.runProgram(code);
      int s = tape.readNumber(2);
      if (s != v + 1337) {
         std::cout << "** UNAUTHORIZED **\n";  // failure
         return 1;
      }
   }
   
   // print flag
   std::ifstream f("flag.txt");
   std::cout << f.rdbuf() << '\n';

   return 0;
}

//EOF

