/* binary (0/1 only) Turing machine in 2D (sheet instead of tape)

   to save on states required, allow "no move" operation

   all classes are totally public

*/

#ifndef turing2d_H
#  define turing2d_H  

#include <iostream>
#include <vector>
#include <string>
#include <exception>



const int DBG = 0;
//const int DBG = 1;
//const int DBG = 2;


//=== Turing code ====
//

// for string -> code, assume -1 <= state <= 62 (64 options only) and use base64 mapping
//
// 8 * symbol + move & state mapped in turn -> 2 characters/action
// state = -1 is mapped to 63
//
// - not space-efficient, but definitely more human-readable

unsigned char decode64(char c) {
   if ((c <= 'Z') && (c >= 'A')) return c - 'A';         // A-Z:  0-25
   if ((c <= 'z') && (c >= 'a')) return (c - 'a') + 26;  // a-z: 25-51
   if ((c <= '9') && (c >= '0')) return (c - 'a') + 52;  // 0-9: 52-61
   if (c == '+') return 62;
   if (c == '/') return 63;
   return 0; // FIXME: crude but definite
}

char encode64(unsigned char v) {
   if (v <= 25) return 'A' + v;
   if (v <= 51) return 'a' + (v - 26);
   if (v <= 61) return '0' + (v - 52);
   if (v == 62) return '+';
   if (v == 63) return '/';
   return '#'; // breaks invertibility but at least signals out of range
}


// one action (write, move, state) 
struct Action {
   char symbol; // what to write (0/1) at current position
   int move;    // where to move (stay, up, right, down, left = 0, 1, 2, 3, 4)
   int state;   // new state

   Action() : state(-1) { } // initialize with terminate state

   Action(char sym, int m, int st) : symbol(sym), move(m), state(st)  {  }

   Action(const std::string& s) {
      if (s.length() == 2) {
         int v = decode64(s[0]);
         symbol = v >> 3;
         move = v & 7;
         state = decode64(s[1]);   // map 63 -> -1
         if (state == 63) state = -1;
      }
      else (*this) = Action(0, -1, 0);
   }

   std::string toString() const {
      const char str[] = { encode64(symbol * 8 + move), encode64((state != -1) ? state : 63), 0 }; 
      return std::string(str);
   }
}; //Action


// one line of Turing code (action on 0, action on 1)
struct CodeLine {
   Action line[2];   // line[i] is action on 'i'

   CodeLine(char sym1, int m1, int st1,  char sym2, int m2, int st2) {
      line[0] = Action(sym1, m1, st1);
      line[1] = Action(sym2, m2, st2);
   }
   
   CodeLine(const std::string& s) {
      if (s.length() == 4) {
        line[0] = Action(s.substr(0, 2));
        line[1] = Action(s.substr(2));
      }
      else (*this) = CodeLine(0, -1, 0,  0, -1, 0); // return an illegal move (terminator) state on error
   }

   std::string toString() const {  return line[0].toString() + line[1].toString();   }

   bool isEnd() const {  return line[0].move == -1 || line[1].move == -1;   }
 
};


struct Program : std::vector<CodeLine> {

   Program() {  }  // empty 

   Program(const CodeLine* lines) {
      for (int i = 0; ! lines[i].isEnd(); i ++) this->push_back(lines[i]);
   }

   Program(const std::string& s) { 
      for (uint pos = 0; pos < s.length(); pos += 4) {
         push_back(CodeLine(s.substr(pos, 4)));
      }      
   }

   std::string toString() const {
      std::string ret;
      for (auto& cl : *this) ret += cl.toString();
      return ret;
   }

};



//=== 2D TAPE ===

// 2D Turing "tape", 0s and 1s only

enum { STAY, UP, RIGHT, DOWN, LEFT };


struct Tape2D {
  
   char* sheet;
   int xsize, ysize, N;

   int linearIdx(int x, int y) {  
      int idx = y * (xsize + 1) + x;
      if ((idx < 0) || (idx >= N)) throw("OFF_SHEET");
      return idx; 
   }

   void set(int x, int y, char val) {  sheet[linearIdx(x, y)] = val;  }

   char get(int x, int y) {  return sheet[linearIdx(x, y)];  }

   Tape2D(int xs, int ys): xsize(xs), ysize(ys) { 
      // FIXME: no checks for null ptr, positive sizes
      N = (xsize + 1) * (ysize + 1);
      sheet = new char[N];
      // keep left and top edges always zero (to mark edges of writeable sheet)
      for (int x = 0; x <= xsize; x ++) set(x, 0, 0);
      for (int y = 1; y <= ysize; y ++) set(0, y, 0);
   }

   void print(std::ostream& f) {
      for (int y = 0; y <= ysize; y ++) {
         for (int x = 0; x <= xsize; x ++) {
            f << (get(x, y) != 0 ? "*" : " ");
         }
         f << '\n';
      }//y
   }

   // read number in top left corner
   //
   // format:   *********************   filled baseline
   //           **  *                   each digit is a contiguous column (length = digit value)
   //           *   *                   padded with empty space to column length = base
   //
   // leftmost digit is lowest value, e.g., 13 given with 5 digits in base 2 (i.e., as 01101) would be
   //
   //           *****
   //           *.**.
   //           ..... 
   //        
   // return -1 for malformed numbers (column too long, or no empty padding to full length)
   //
   // FIXME: no guard against integer overflow
   //
   int readNumber(int base) {
      if (base <= 1) return -1;   // must have base > 1
      int num = 0;
      for (int x = 1, multiplier = 1; true; x ++, multiplier *= base) {  // baseline position
         // read one column`
         int y = 1;
         if (get(x, y) == 0) return num;   // baseline ended
         for (y = 2; (y <= base) && get(x, y) != 0;  y ++) ;    // digit
         int digit = y - 2;
         if (digit == base) return -1;      // column too long
         for (; (y < base + 2) && get(x, y) == 0; y ++)  ;      // padding
         if (y != base + 2) return -1;  // insufficient padding
         num += multiplier * digit;
      }
   }
   
   // write a number in the format explained at readNumber, with baseline at yoffset,
   // using as few digits as necessary, but do write at least minDigits digits
   void writeNumber(int v, int base, int yoffset = 1, int minDigits = 1) {
      for (int x = 1; true; x ++, v /= base) {
         int digit = v % base;
         for (int y = yoffset; y <= yoffset + digit; y ++)  set(x, y, 1);
         for (int y = yoffset + digit + 1; y <= yoffset + base; y ++) set(x, y, 0);
         if (v == 0 && x > minDigits) {
            set(x, yoffset, 0);  // erase baseline in terminator column
            break;
         }
      }//x
   }

   // put two numbers in top left column (used in tests only, not in challenge)
   void write2Nums(int v1, int v2, int base) {
      writeNumber(v1, base, 1);
      writeNumber(v2, base, base + 1); // FIXME: we could also omit baseline if v1 has no fewer digits than v2
   }   


   void runProgram(const Program& prog) {
      int state = 0;      // start from state = 0
      int x = 1, y = 1;  // at (1,1) on sheet
      while (true) {
         try {  
            const CodeLine& line = prog.at(state);
            char symbol = get(x, y);
            const Action& act = line.line[(int)symbol];
            set(x, y, act.symbol);
            if (DBG >= 1) {
               std::cout << "state=" << state << ",  (x,y)=" << x << "," << y << ",  symbol=" << symbol << '\n';
               std::cout << "-> state=" << act.state << ", symbol=" << act.symbol << ", move=" << act.move << '\n';
            }
            if (DBG >= 2) print(std::cout);
            state = act.state;
            switch (act.move) {
            case 0: { break; }         // stay
            case 1: { y --;  break; }  // up
            case 2: { x ++;  break; }  // right
            case 3: { y ++;  break; }  // down
            case 4: { x --;  break; }  // left
            default:  throw("INVALID_MOVE"); // invalid
            }//switch
         } catch(const std::exception& ex) { 
            if (DBG >= 2) std::cout << "TERM: general EX\n";
            break;    // terminate on nonexistent state (typically -1)
         } catch(const char* ex) {
            if (DBG >= 2) std::cout << "TERM: " << ex << "\n";
            break;    // terminate if we go off sheet, or move is invalid
         }//exceptions
      }// while
   }//runProgram

}; //Tape2D



#endif /* ! turing2d_H */
//EOF

