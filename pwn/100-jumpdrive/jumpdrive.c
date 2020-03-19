#include <stdlib.h>
#include <stdio.h>

int main() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  printf("Charging up the jump drive...\n");

  FILE * f = fopen("flag.txt", "r");
  int a = 0;
  char *b;
  char c;
  double d = 3.1337;
  int e = 0xdeadbeef;

  char buf[31];
  int i = 0;

  printf("Reading the destination coordinates...\n");

  while ((c = fgetc(f)) != EOF) {
    buf[i++] = c;
  }

  buf[i] = '\0';

  printf("Where are we going?\n");

  char input[64];
  fgets(input,64,stdin);

  printf(input);
}
