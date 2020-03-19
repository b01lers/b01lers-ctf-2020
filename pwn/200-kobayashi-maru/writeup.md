This challenge was inspired by an impossible game - Kobayashi Maru from Startrek. If you run the code (or read it all) you will see that no matter what you do, in the end you lose. Lets dive into the binary and code.

```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

So we have no pie which means we know the addresses of functions in the binary and there is only partial RELRO so we can overwrite PLT.

So here is the code, its long and I'm sorry if you had to reverse it. Its mostly printing, but still.

```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

/* Simulation of the Kobayashi Maru rescue mission */

void simulation();
void give_decision_one();
void interpret_decision_one(unsigned int);
void present_choices_two();

void order_nyota_first();
void order_janice_first();
void order_scotty_first();
void order_leonard_first();

void order_nyota_second(unsigned int);
void order_janice_second(unsigned int);
void order_scotty_second(unsigned int);
void order_leonard_second(unsigned int);

void order_nyota_third(unsigned int);
void order_janice_third(unsigned int);
void order_scotty_third(unsigned int);
void order_leonard_third(unsigned int);

void order_nyota_fourth(unsigned int);
void order_janice_fourth(unsigned int);
void order_scotty_fourth(unsigned int);
void order_leonard_fourth(unsigned int);

void my_fgets(char *s, int size, FILE *stream) {
  char c = '\0';
  int fd = fileno(stream);
  int count = 0;

  while (count <= size) {
    read(fd, &c, 1);
    if (c == '\n') {
      break;
    } else {
      s[count++] = c;
    }
  }
}

int main() {
  setvbuf(stdin, 0, 2, 0); 
  setvbuf(stdout, 0, 2, 0);

  simulation();
}

void simulation() {
  char choice = 0;

  give_decision_one();
  my_fgets(&choice, 1, stdin);
  interpret_decision_one(choice - 0x30);

  present_choices_two();
}

void give_decision_one() {
  printf("Kirk, we have received a distress signal from a nearby ship, the Kobayashi Maru. They have a full crew on board and their engine has broken down\n\n");
  printf("We have the following options:\n");
  printf("[1]: Proceed to the ship with shields down, ready to beam their crew members aboard (quick rescue)\n");
  printf("[2]: Proceed to the ship with shields up, prepared for any enemy ships (longer rescue)\n");
  printf("[3]: Charge photon lasers and fire on the ship because you think it is an ambush (no trust)\n");
  printf("Choice: ");
}

void interpret_decision_one(unsigned int choice) {
  printf("\n\n");
  switch (choice) {
    case 1:
      printf("As you near the Kobayashi Maru, another ship comes out of nowhere and immediately fires upon you. Your shields were down and as a result your ship was destroyed\n\n");
      exit(1);
      break;

    case 2:
      printf("Another ship comes out of nowhere as you approach and fires upon you. Your shields have blocked the first volley of fire, but are significantly weakened\n\n");
      return;

    case 3:
      printf("You have just claimed the lives of a whole crew of innocent people. You should be ashamed of yourself, you're obviously not cut out to be in Starfleet\n\n");
      exit(1);
      break;

    default:
      printf("You can't even communicate and make the easiest of decisions. Come back when you've learned how to read and write\n");
      exit(1);
  }
}

void present_choices_two() {
  char member_name[8] = {0};

  printf("Which one of your first mates do you want to give orders to first?\n");
  printf("Nyota\n");
  printf("Leonard\n");
  printf("Scotty\n");
  printf("Janice\n");
  printf("Type the member's name: ");

  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  printf("\n\n");

  if (!strncmp(member_name, "Nyota", 5)) {
    order_nyota_first();
  } else if (!strncmp(member_name, "Leonard", 7)) {
    order_leonard_first();
  } else if (!strncmp(member_name, "Scotty", 6)) {
    order_scotty_first();
  } else if (!strncmp(member_name, "Janice", 6)) {
    order_janice_first();
  } else {
    printf("You don't even know your own crew. You would make a terrible captain\n");
    exit(1);
  }
}

/* ... Tons of functions in here that I left out because they don't do anything for the exploit */

void order_leonard_fourth(unsigned int mask) {
  (void)(mask);
  
  printf("Everything is dark. The enemy ship has beamed a boarding crew aboard and there is nothing for you to do. They have released gas in the ship and you are becoming incoherent.");
  printf("Do you have any dying words?\n");

  char death_message[20] = {0};
  my_fgets(death_message, 19, stdin);

  // NOTE: Vuln here
  printf(death_message);
  
  exit(-1);
}
```

So once again if we look at order\_leonard\_fourth, we see that there is a format string vulnerability. There is only one printf vulnerability at the end of the program and then it exits, which isn't enough to get a shell. In order to exploit this program you must know about format strings "%n" modifier which will write to a specified address. You must also know about how linked library functions find their address via the PLT and how we can hijack that. And then finally you have to know that no pie means we know the address of all of the user written code.

First step in this exploit is make it so that exit will not actually exit. This is where our knowledge of the PLT/GOT comes in. We use printf to overwrite exit@got with the address of order\_leonard\_fourth. This allows us to exploit the printf vulnerability multiple times because exit will go to order\_leonard\_fourth instead of exiting.

Next up we need to find the address of libc (any address in libc, then calculate the base of the address based on that). I did this by breaking in gdb at the printf call, then examined the stack contents with "x/30x $esp" which prints the first 30 words on the stack. I then used "info proc mappings" to check where libc is currently loaded in memory. I looked for something on the stack in the range of where libc is loaded and found there was one at the 7th word up the stack. We then leak this and now know where libc is loaded and therefore where all of its functions are located.

Now we want to call system("/bin/sh"), but how can we do that. Well we can use the same trick we used with exit to overwrite another libc call, but we also need to pass the argument "/bin/sh" which is a bit harder. If you look at present\_choices\_two() there is a call to strncmp where the first argument is user controlled. This is a perfect candidate to overwrite. So the next part of the exploit is to overwrite strncmp@got with system.

After this we are still only hitting the order\_leonard\_fourth function, so we need to overwrite exit to point to main (or present\_choices\_two) so that we can hit the call to "strncmp" which is actually system now. The program will prompt for who we want to order next and then we enter "/bin/sh" which calls system("/bin/sh") and then a shell is spawned for you.