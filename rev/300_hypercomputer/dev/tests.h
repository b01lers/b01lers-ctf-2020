/*== TESTS ==*/

void TEST0(struct Tape* tp) {    // read-write
   int a = 40, b = 30;
   writeNum2(a, b, tp);
   int c = readNum(tp);
   printf("c=%d\n", c);   
   printTape(tp, 100);
}

void TEST1(struct Tape* tp) {   // addition
   // do a + b
   printTape(tp, 100);
   printf("40+30=%d\n", add(40, 30, tp));   
   printTape(tp, 100);
   printf("0+30=%d\n", add(0, 30, tp));   
   printTape(tp, 100);
   printf("30+0=%d\n", add(30, 0, tp));   
   printTape(tp, 100);
   printf("0+0=%d\n", add(0, 0, tp));   
   printTape(tp, 100);
}

void TEST2(struct Tape* tp, int nmax) { // sum(nmax)
   printf("sum(%d)=%d\n", nmax, sumInt(nmax, tp));
}

void TEST3(struct Tape* tp) {
   int vals[5] = {0, 1, 2, 5, 10};
   for (int i = 0; i < 5; i ++) {
      if (i > 0) printf(",  ");
      int a = vals[i];
      printf("mod2(%d)=%d", a, mod2(a, tp));
   }
   printf("\n");
}

void TEST4(struct Tape* tp) {
   int vals[5] = {0, 1, 2, 5, 10};
   for (int i = 0; i < 5; i ++) {
      if (i > 0) printf(",  ");
      int a = vals[i];
      printf("(%d!=0)=%d", a, nonzero(a, tp));
   }
   printf("\n");
}

void TEST5(struct Tape* tp) {
   printf("20-20=%d, ", sub(20, 20, tp));
   printf("20-0=%d, ", sub(20, 0, tp));
   printf("20-19=%d, ", sub(20, 19, tp));
   printf("0-0=%d, ", sub(0, 0, tp));
   printf("1-1=%d, ", sub(1, 1, tp));
   printf("1-0=%d\n", sub(1, 0, tp));
}

void TEST6(struct Tape* tp) {
   int vals[5] = {0, 1, 2, 5, 10};
   for (int i = 0; i < 5; i ++) {
      if (i > 0) printf(",  ");
      int a = vals[i];
      printf("(%d/2)=%d", a, div2(a, tp));
   }
   printf("\n");
}

void TEST7(struct Tape* tp) {
   int vals[4] = {1, 2, 5, 10};
   printf("sum(1,2,5,10)=%d\n", sum(4, vals, tp));
   int vals2[7] = {32, 11, 1, 18, 7, 20, 3};
   printf("sum(32,11,1,18,7,20,3)=%d\n", sum(7, vals2, tp));
}

void TEST8(struct Tape* tp) {
   printf("20-20=%d, ", sub0(20, 20, tp));
   printf("20-0=%d, ", sub0(20, 0, tp));
   printf("20-19=%d, ", sub0(20, 19, tp));
   printf("0-0=%d, ", sub0(0, 0, tp));
   printf("1-1=%d, ", sub0(1, 1, tp));
   printf("1-0=%d\n", sub0(1, 0, tp));
   printf("0-20=%d, ", sub0(0, 20, tp));
   printf("19-20=%d, ", sub0(19, 20, tp));
   printf("0-1=%d\n", sub0(0, 1, tp));
}


void TEST9(struct Tape* tp) {
   printf("cmp(20,20)=%d, ", cmp(20, 20, tp));
   printf("cmp(20,0)=%d, ", cmp(20, 0, tp));
   printf("cmp(20,19)=%d, ", cmp(20, 19, tp));
   printf("cmp(0,0)=%d, ", cmp(0, 0, tp));
   printf("cmp(1,1)=%d, ", cmp(1, 1, tp));
   printf("cmp(1,0)=%d\n", cmp(1, 0, tp));
   printf("cmp(0,20)=%d, ", cmp(0, 20, tp));
   printf("cmp(19,20)=%d, ", cmp(19, 20, tp));
   printf("cmp(0,1)=%d\n", cmp(0, 1, tp));
}


void TEST10(struct Tape* tp) {
   int vals[5] = {0, 1, 2, 5, 10};
   for (int i = 0; i < 5; i ++) {
      if (i > 0) printf(",  ");
      int a = vals[i];
      printf("(%d*2)=%d", a, mul2(a, tp));
   }
   printf("\n");
}


void TESTall(struct Tape* tp) {
   TEST0(tp);        // read-write
   TEST1(tp);        // addition
   TEST2(tp, 125);   // sum(n) using add(a,b)
   TEST3(tp);        // mod2(n)                                                                                            TEST4(tp);        // nonzero(n)
   TEST4(tp);        // nonzero
   TEST5(tp);        // subtraction (a>=b>=0)
   TEST6(tp);        // division by 2
   TEST7(tp);        // sum(n) directly
   TEST8(tp);        // max(a-b,0)
   TEST9(tp);        // cmp(a,b)
   TEST10(tp);       // mul2(a)
}

/* EOF */
