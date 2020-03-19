Author: maczilla
Category: Pwn
Points: 100

```c
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Function Definitions
void list_previous_purchases(void);
void lose(void);
void win(void);
void buy_starship(unsigned int *);

/* Meshuggah 2.0 - Used Starship Dealer
 *
 * gcc meshuggah.c -z execstack -o meshuggah
 */

int main(int argc, char **argv) {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  srand(time(0) + 2);
  unsigned int credits = 1000;
  int customer_number = 4;

  list_previous_purchases();

  while (true) {
    if (credits <= 0) {
      lose();
    }

    if (customer_number >= (100 - 4)) {
      win();
    }

    buy_starship(&credits);
    customer_number++;
  }
}

void list_previous_purchases(void) {
  printf("Welcome to the Used Car Dealership, we hope you are ready for the insane savings ahead of you!\n");
  printf("Here are the first three starships which were purchased today for an incredible 90%% savings. Each starship costs a mere 10 credits when on sale, but we only put one on sale at a time\n\n");

  printf("1. Meshuggah-%d\n", rand());
  printf("2. Meshuggah-%d\n", rand());
  printf("3. Meshuggah-%d\n\n", rand());

  printf("I don't even know how Meshuggah comes up with their model names, but I don't care because everyone buys them\n");
}

void lose(void) {
  printf("\nYou have to be smarter with your money. We have sales to save you money, you shouldn't be buying these starships at full price. They're never worth it at that cost\n");
  exit(1);
}

void win(void) {
  FILE *file = fopen("./flag.txt", "r");
  char code = '\0';
  while (true) {
    code = (char)fgetc(file);

    if (code == EOF) {
      exit(0);
    } else {
      putc(code, stdout);
    }
  }
}

void buy_starship(unsigned int *credits) {
  printf("\nWhich model starship would you like to buy? ");
  int user_model_choice = 0;
  scanf("%d", &user_model_choice);

  int model_on_sale = rand();

  if (user_model_choice == model_on_sale) {
    printf("You're a smart one, picking the one on sale!\n");
    *credits -= 10;
  } else {
    printf("Thats gonna be an expensive one... Glad you're buying from me! And please come back after that one breaks down.\n");
    *credits -= 100;
  }
}
```

Again I'll be using the source code to explain the vulnerability. This just makes it easier to explain than stepping through assembly and is more accessible to everyone.

Running this program blindly it looks like a used starship dealer who is selling some starships for a very nice discount. It prints some of the ships that were put on sale recently (3 to be exact) and then  Now lets dive into the code.

So we have a win function which prints out flag.txt, awesome. If you look through the code more you see that win is called if some variable is greater than or equal to 96 (this gets optimized to 92 in the binary since the variable is initialized to 4). So now lets see how this variable gets updated. It only gets handled in buy\_starship. buy\_starship will first asak the user for a number using scanf("%d") and then generate a random number. If the user input equals the random number then the starship was on sale and only costs 10 credits. Otherwise it wasn't on sale and it costs 100 credits. We start with 1000 credits and need to buy 92 ships so that means every single purchase we make must be on sale. So how can we predict the random number correctly?

Looking at the man page for rand you can see that srand can be used to seed the random function. If two separate programs are seeded with the same number, then they will produce the same random numbers in the same order. In this program you can see that srand is called with time(0) + 2 which is the current time in seconds plus 2. This is very insecure because we know approximately when the program will be run since its about when we connect to it (depending upon latency to the remote server). But to account for this the program also prints out three randomly generated numbers which are the first three starships that the dealership sold today which can be used to check that you have the correct seed. After the correct seed is confirmed then we just have to send the next 92 random numbers line by line and then we will get to the win function!

See the solver for how to do this with pwntools

Other notes - Execstack is turned on here just to make people think about trying to get shellcode to run, but there are no vulnerabilities in here that would lead to that