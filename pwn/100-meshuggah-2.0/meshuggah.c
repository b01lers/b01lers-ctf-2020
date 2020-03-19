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
