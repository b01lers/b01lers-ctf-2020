# Jumpdrive

## Category
PWN
## Points:
100
## Description:
Dave is running away from security at the DFV. Help him reach safety
## Creator:
maczilla

## Solve

```c
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

  /* Read flag.txt onto the stack */
  while ((c = fgetc(f)) != EOF) {
    buf[i++] = c;
  }

  buf[i] = '\0';

  printf("Where are we going?\n");

  /* Safely fgets 64 bytes into input */
  char input[64];
  fgets(input,64,stdin);

  /* Printf input directly: printf vulnerability */
  printf(input);
}
```

As seen above in jumpdrive.c, we read in the flag file to the stack, then safely get 64 bytes into the buffer, and then we print the input. This seems innocent enough, but the problem is the program uses user input directly as the format specifier. In variadic argument functions (like printf) arguments are pushed  onto the stack (in 64 bit there are 6 registers used as the first 6 arguments and then the stack is used). The format specifier in printf tells printf which arguments to print and how to print them (hex, decimal, use it as a string pointer, etc). Since we control the format string and no arguments were given to printf, it will start reading up the stack if we pass format string specifiers like %x!

```
$ ./jumpdrive
Charging up the jump drive...
Reading the destination coordinates...
Where are we going?
%x.%x.%x.%x.
b05ba570.315868d0.312a9081.315868c0.
```

As you can see above, we entered some %x's separated by dots to differentiate from one argument on the stack vs another. So now it should be possible to print out the stack by just plopping in a bunch of %x in the buffer, but we don't know for sure if that will have enough prints in it to get to the flag. This is where another very helpful printf construct comes in, the argument specifier. You can use "%n$x" to print the nth argument up the stack as hex. You can use this to keep trying different arguments up the stack until you find hex that decodes to "pctf". That is the easier, but guess and check way to do this. 

The calculated way to do this is in gdb. First break when buf is used and record its starting address. You could find this by using peda's searchmem function to find a dummy flag in memory when running locally (but make sure you use the stack address and not the heap address). Then break at the call to printf(input) and see what $rsp is. This is the stack pointer and tells you where printf will begin reading from the stack (after the first 6 registers). You can take the difference between these two values, divide by 8 since each word in a 64 bit program is  8, and then add 6 to account for printf using 6 registers first. After all of this has been done that number should be the number which you use in your format string attack to print the beginning of the flag.

```
&buf = 0x7fffffffdc30
rsp @ printf = 0x7fffffffdc10
((0x7fffffffdc30 - 0x7fffffffdc10) / 8) + 6 = 10
```

Now lets try using the number we calculated. The addresses will not be the same on every run but the relative offset between the printf and the address of buf they should be the same.

```
$ ./jumpdrive
Charging up the jump drive...
Reading the destination coordinates...
Where are we going?
%10$x
66746370
```

If we unhexlify this string in python we get "ftcp". Its "pctf" backwards! This happens due to little endianness. So using this we can print consecutive regions of stack (10th argument then 11th then 12th and so on) until you find the closed brace of the flag. The solver does this the crude way, but I will leave you to try to implement the calculated solver if you wish.

See solve.py for the solver. Its definitely not the prettiest solver, but it works :)
