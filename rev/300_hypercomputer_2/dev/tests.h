/* 
    some Turing and hybrid codes for testing
*/

#include <iostream>

#include "turing2d.h"


//=== 2D TURING PROGRAMS ==


// increment by one, in base 2: O(ln n)
const CodeLine PROGinc[6] = {
   // state 0: carry = 1 at current digit (tape must be at baseline)
   // state 1: carry = 0 at current digit
   // state 2: like 1 but with carry = 1
   CodeLine(1, RIGHT,  4,   1, DOWN,   2),     // #0, check baseline, if none, extend it (R->#4), 1: DOWN->#2  
   CodeLine(0, UP,    -1,   1, UP,    -1),     // #1 (carry = 0), keep current & UP, terminate
   CodeLine(1, UP  ,  -1,   0, UP,     3),     // #2 flip current & UP; if result is 1: terminate; 0: (carry=1) UR to next digit( ->#3->#0)
   CodeLine(1, RIGHT,  0,   1, RIGHT,  0),     // #3 R->0
   CodeLine(0, LEFT,   0,   0, LEFT,   0),     // #4 terminate baseline: erase,L, ->#0
   CodeLine(0, -1,     0,   0, -1,     0)      //END
};

const std::string CODEinc("KELCB/J/J/BDKAKAEAEA");



// add 1337 to a number (1337 = 1 + 8 + 16 + 32 + 256 + 1024 = *..***.*.*)
//
// option A: write 1337 on the sheet and then follow with a general add code
// option B: apply the increment-by-one code 6 times with shifted starting positions (~30 ops + repositioning)
// option C: like B but in 2s complenment
// option D: go through digits and branch based on whether to add 0/1, or 1/2 (depending on C, and corresponding digit in 1337)
//           -> 2*n_digits ~ 30 ops  => CLEANEST LOGIC, SO PICK THIS
//           state 2 * i + j means "about to add to the i-th digit with carry=j"
//           state 0 means D
//           state 1 means add 1 to digit 0 (at this point C=0 always)
//
//
// 17-bit version (assumes 17 digits and updates baseline on overflow) -> works 100% for hypercomputer2 challenge
const CodeLine PROGleetD[] = {
   CodeLine(1, DOWN,   1,   1, DOWN,   1),   // #0 D

   CodeLine(1, RIGHT,  2,   0, RIGHT,  3),   // #1: +1, R      bit 0*

   CodeLine(0, RIGHT,  4,   1, RIGHT,  4),   // #2: +0, R      bit 1
   CodeLine(1, RIGHT,  4,   0, RIGHT,  5),   // #3: +1, R

   CodeLine(0, RIGHT,  6,   1, RIGHT,  6),   // #4: +0, R      bit 2
   CodeLine(1, RIGHT,  6,   0, RIGHT,  7),   // #5: +1, R

   CodeLine(1, RIGHT,  8,   0, RIGHT,  9),   // #6: +1, R      bit 3*
   CodeLine(0, RIGHT,  9,   1, RIGHT,  9),   // #7: +2, R

   CodeLine(1, RIGHT, 10,   0, RIGHT, 11),   // #8: +1, R      bit 4*
   CodeLine(0, RIGHT, 11,   1, RIGHT, 11),   // #9: +2, R

   CodeLine(1, RIGHT, 12,   0, RIGHT, 13),   //#10: +1, R      bit 5*
   CodeLine(0, RIGHT, 13,   1, RIGHT, 13),   //#11: +2, R

   CodeLine(0, RIGHT, 14,   1, RIGHT, 14),   //#12: +0, R      bit 6
   CodeLine(1, RIGHT, 14,   0, RIGHT, 15),   //#13: +1, R

   CodeLine(0, RIGHT, 16,   1, RIGHT, 16),   //#14: +0, R      bit 7
   CodeLine(1, RIGHT, 16,   0, RIGHT, 17),   //#15: +1, R

   CodeLine(1, RIGHT, 18,   0, RIGHT, 19),   //#16: +1, R      bit 8*
   CodeLine(0, RIGHT, 19,   1, RIGHT, 19),   //#17: +2, R
    
   CodeLine(0, RIGHT, 20,   1, RIGHT, 20),   //#18: +0, R      bit 9
   CodeLine(1, RIGHT, 20,   0, RIGHT, 21),   //#19: +1, R
 
   CodeLine(1, RIGHT, 22,   0, RIGHT, 23),   //#20: +1, R      bit 10*
   CodeLine(0, RIGHT, 23,   1, RIGHT, 23),   //#21: +2, R

   CodeLine(0, RIGHT, 24,   1, RIGHT, 24),   //#22: +0, R      bit 11
   CodeLine(1, RIGHT, 24,   0, RIGHT, 25),   //#23: +1, R

   CodeLine(0, RIGHT, 26,   1, RIGHT, 26),   //#24: +0, R      bit 12
   CodeLine(1, RIGHT, 26,   0, RIGHT, 27),   //#25: +1, R
 
   CodeLine(0, RIGHT, 28,   1, RIGHT, 28),   //#26: +0, R      bit 13
   CodeLine(1, RIGHT, 28,   0, RIGHT, 29),   //#27: +1, R
 
   CodeLine(0, RIGHT, 30,   1, RIGHT, 30),   //#28: +0, R      bit 14
   CodeLine(1, RIGHT, 30,   0, RIGHT, 31),   //#29: +1, R
 
   CodeLine(0, RIGHT, 32,   1, RIGHT, 32),   //#30: +0, R      bit 15
   CodeLine(1, RIGHT, 32,   0, RIGHT, 33),   //#31: +1, R
 
   CodeLine(0, RIGHT, -1,   1, RIGHT, -1),   //#32: +0, R      bit 16
   CodeLine(1, RIGHT, -1,   0, RIGHT, 34),   //#33: +1, R
 
   CodeLine(1, UP,    34,   1, UP,    34),   //#34: write, U   on overflow to bit 17, create baseline, then TERM
   CodeLine(1, RIGHT, 35,   1, RIGHT, 35),   //#35: write, R
   CodeLine(0, RIGHT, -1,   0, RIGHT, -1),   //#36: erase, TERM
 
   CodeLine(0, -1,     0,   0, -1,     0)      //END
 
};

// same code as string
const std::string CODEleetD2("LBLBKCCDCEKEKECFCGKGKGCHKICJCJKJKKCLCLKLKMCNCNKNCOKOKOCPCQKQKQCRKSCTCTKTCUKUKUCVKWCXCXKXCYKYKYCZCaKaKaCbCcKcKcCdCeKeKeCfCgKgKgChC/K/K/CiJiJiKjKjC/C/");


// test code for off-sheet termination
const CodeLine PROGtest[3] = {
   CodeLine(0, UP,  1,   0, UP,  1),
   CodeLine(0, UP, -1,   0, UP, -1),
   CodeLine(0, -1,  0,   0, -1,  0)    //END
};


//=== HYBRID CODES ==

int hybrid_inc(int v, Tape2D& tp) {
   tp.writeNumber(v, 2);
   if (DBG) tp.print(std::cout);
   Program prog(& PROGinc[0]);
   //Program prog(CODEinc);
   if (DBG >= 2) std::cout << prog.toString() << '\n';
   tp.runProgram(prog);
   return tp.readNumber(2);
}

int hybrid_leet(int v, Tape2D& tp) {
   tp.writeNumber(v, 2);
   if (DBG >= 1) tp.print(std::cout);
   Program prog(& PROGleetD[0]);
   if (DBG >= 2 || true) std::cout << prog.toString() << '\n';
   exit(1);
   tp.runProgram(prog);
   return tp.readNumber(2);
}


//=== TESTS ==

// readNumber test (bases 2 and 5)
void TEST1(Tape2D& tape) {
   while(true) {
     tape.print(std::cout);
     int num2 = tape.readNumber(2);
     std::cout << num2 << '\n';
     int num5 = tape.readNumber(5);
     std::cout << num5 << '\n';
     int x, y, v;
     std::cout << "x,y,v:";
     std::cin >> x >> y >> v;
     tape.set(x, y, v);
   }
}//TEST1

// writeNumber test
void TEST2(Tape2D& tape) {
   while(true) {
      tape.print(std::cout);
      std::cout << "v, base, offset, minDigits:";
      int v, base, offset, minDigits;
      std::cin >> v >> base >> offset >> minDigits;
      tape.writeNumber(v, base, offset, minDigits);
   }
}//TEST2


// write2Nums test
void TEST3(Tape2D& tape) {
   while(true) {
      tape.print(std::cout);
      std::cout << "v1, v2, base:";
      int v1, v2, base;
      std::cin >> v1 >> v2 >> base;
      tape.write2Nums(v1, v2, base);
   }
}//TEST3


// increment test
void TEST4(Tape2D& tape) {
   while(true) {
      tape.print(std::cout);
      std::cout << "v:";
      int v;
      std::cin >> v;
      v = hybrid_inc(v, tape);
      std::cout << v << '\n';
   }
}//TEST4

// some more tests... [REDACTED]

// random leet test
void TEST7(Tape2D& tape) {
   for (int i = 0; i < 100; i ++) {
      int rval = rand();
      int v = (rval & 0xffff) + 0x10000;   //   [1-2] * 65536
      int s = hybrid_leet(v, tape);
      if (s != v + 1337) {
         std::cout << v <<  ' ' << s << ' ' << v + 1337 << '\n';
      }
   }
}



// EOF
