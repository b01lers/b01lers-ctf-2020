// some string operations used in the challenge (and their inverses for creating the challenge)

#include <string.h>


// swap parts [0,pos-1] and [pos, len-1], with first part reversed before swap
// A|B -> B|rev(A)
void swap(unsigned char* s, int pos) { 
   int n, i;
   unsigned char tmp[200];

   tmp[0] = 0;
   n = strlen(s);
   strncat(tmp, s,  pos); // save front part [0, pos - 1]
   for (i = 0; i < n - pos; i ++) s[i] = s[i + pos];  // shift [pos, len-1] to front
   for (i = 0; i < pos; i ++) s[i + n - pos] = tmp[pos - i - 1]; // copy saved part to back, swapped  
}

void roll(unsigned char* s, int shft, int pos) {  // roll chars by a certain amount in [0,pos-1], nonzero chars assumed!
   int i;
   for (i = 0; i < pos; i ++) {
      unsigned char c = ((s[i] + 509 + shft) % 255) + 1; // +2*255-1 to avoid negative numbers
      //printf("%d %d %d\n", s[i], shft, c);
      s[i] = c;  
   }
}

#ifdef CREATE

// inverse of swap(s, pos)
// B|rev(A) -> A|B
void invswap(unsigned char* s, int pos) { // swap [0, len-pos-1] and [len-pos, len-1], with second part reversed befor swap
   int n, i;
   unsigned char tmp[200];

   tmp[0] = 0;
   n = strlen(s);
   strcat(tmp, s + n - pos); // save tail
   for (i = n - pos - 1; i >= 0; i --) s[i + pos] = s[i]; // shift front [0, len-pos-1] to back
   for (i = 0; i < pos; i ++) s[i] = tmp[pos - i - 1];  // copy saved part to front, swapped
}

// inverse of roll(s,a) is roll(s,-a)

#endif

//EOF
