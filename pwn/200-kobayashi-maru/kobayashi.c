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

void order_nyota_first() {
  char choice = 0;

  printf("What would you like Nyota to do?\n");
  printf("[1] Prepare medical bay\n");
  printf("[2] Protect Scotty\n");
  printf("[3] Protect Leonard\n");
  printf("[4] Protect Janice\n");
  printf("[5] Protect yourself (Kirk)\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("While Nyota was prepping the medical bay, the enemy ship fired off a weak set of guns which broke the shields down. A few crew members were hurt from the impact\n");
      break;

    case 2:


    case 3:


    case 4:
      
      printf("While Nyota was protecting a crew member the enemy ship was able to charge another shot and fire upon the ship. This shot destroyed the whole ship\n");
      exit(1);
      break;

    case 5:
      printf("Putting yourself above the crew is a terrible way to think. You fail\n");
      exit(1);
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  unsigned int mask = (1 << 1);
  char member_name[8] = {0};
  
  printf("Who would you like to order next?\n");
  printf("Leonard\n");
  printf("Scotty\n");
  printf("Janice\n");
  printf("Type the member's name: ");

  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  printf("\n\n");

  if (!strncmp(member_name, "Leonard", 7)) {
    order_leonard_second(mask);
  } else if (!strncmp(member_name, "Scotty", 6)) {
    order_scotty_second(mask);
  } else if (!strncmp(member_name, "Janice", 6)) {
    order_janice_second(mask);
  } else {
    printf("You've forgotten another crew member's name. Favoritism is not looked upon nicely here\n");
    exit(1);
  }
}

void order_leonard_first() {
  char choice = 0;

  printf("What would you like Leonard to do?\n");
  printf("[1] Lock onto the enemy ship for increased accuracy later\n");
  printf("[2] Charge phaser beams\n");
  printf("[3] Fire weak guns\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("After Leonard locked onto the enemy ship, they fired off another volley which destroyed the ship. Everyone died");
      exit(1);
      break;

    case 2:
      printf("While Leonard charged the phaser beams, the enemy ship fired off a more powerful shot which destroyed the ship.");
      exit(1);
      break;

    case 3:
      printf("The weak guns were able to miraculously disable the enemy ships guns with a lucky shot\n");
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  unsigned int mask = (1 << 0);
  char member_name[8] = {0};
  
  printf("Who would you like to order next?\n");
  printf("Nyota\n");
  printf("Scotty\n");
  printf("Janice\n");
  printf("Type the member's name: ");

  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  printf("\n\n");

  if (!strncmp(member_name, "Nyota", 5)) {
    order_nyota_second(mask);
  } else if (!strncmp(member_name, "Scotty", 6)) {
    order_scotty_second(mask);
  } else if (!strncmp(member_name, "Janice", 6)) {
    order_janice_second(mask);
  } else {
    printf("You've forgotten another crew member's name. Favoritism is not looked upon nicely here\n");
    exit(1);
  }
}

void order_scotty_first() {
  char choice = 0;

  printf("What would you like Scotty to do?\n");
  printf("[1] Divert energy from warp drive into shields\n");
  printf("[2] Divert energy from shields into guns\n");
  printf("[3] Divert energy from shields into warp drive\n");
  printf("[4] Divert energy from guns into shields\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("With the additional power from the warp drive the ship survived a second volley from the enemy ship, but the shields are totally down now\n");
      break;

    case 2:

    case 3:
      printf("Scotty powered down the shields by diverting energy away from it and so the second strike from the enemy ship destroyed the ship. Everyone died\n");
      exit(1);
      break;

    case 4:
      printf("With the additional power from the guns the ship survived a second volley from the enemy ship, but the shields are totally down now\n");
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  unsigned int mask = (1 << 2);
  char member_name[8] = {0};
  
  printf("Who would you like to order next?\n");
  printf("Nyota\n");
  printf("Leonard\n");
  printf("Janice\n");
  printf("Type the member's name: ");

  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (!strncmp(member_name, "Nyota", 5)) {
    order_nyota_second(mask);
  } else if (!strncmp(member_name, "Leonard", 7)) {
    order_leonard_second(mask);
  } else if (!strncmp(member_name, "Janice", 6)) {
    order_janice_second(mask);
  } else {
    printf("You've forgotten another crew member's name. Favoritism is not looked upon nicely here\n");
    exit(1);
  }
}

void order_janice_first() {
  char choice = 0;

  printf("What would you like Janice to do?\n");
  printf("[1] Cry in the corner\n");
  printf("[2] Run around screaming\n");
  printf("[3] Hug Nyota for comfort\n");
  printf("[4] Fire off the guns which Janice hasn't been trained on yet\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("Janice managed to cry in the corner loud enough to not hear the ship get hit with another volley. The shields are completely down\n");
      break;

    case 2:
      printf("After running around screaming, Leonard shot Janice right between the eyes. You don't have enough control over your crew, you fail\n");
      exit(1);

    case 3:
      printf("Nyota begrudgingly holds you as you wimper. Both of you fall to the floor after the second volley strikes the shields and then a few shots hit the ship. The shields are completely down\n");
      break;

    case 4:
      printf("Janice knows absolutely nothing about these guns and saw a ship in her sights when she got to it. She immediately fired only to realize that it was another part of her own ship. Everyone died from the whole in the ship.\n");
      exit(1);

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  unsigned int mask = (1 << 3);
  char member_name[8] = {0};
  
  printf("Who would you like to order next?\n");
  printf("Nyota\n");
  printf("Leonard\n");
  printf("Scotty\n");
  printf("Type the member's name: ");

  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (!strncmp(member_name, "Nyota", 5)) {
    order_nyota_second(mask);
  } else if (!strncmp(member_name, "Leonard", 7)) {
    order_leonard_second(mask);
  } else if (!strncmp(member_name, "Scotty", 6)) {
    order_scotty_second(mask);
  } else {
    printf("You've forgotten another crew member's name. Favoritism is not looked upon nicely here\n");
    exit(-1);
  }
}

void order_nyota_second(unsigned int mask) {
  char choice = 0;

  printf("What would you like Nyota to do?\n");
  printf("[1] Prepare medical bay\n");
  printf("[2] Protect Scotty\n");
  printf("[3] Protect Leonard\n");
  printf("[4] Protect Janice\n");
  printf("[5] Protect yourself (Kirk)\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("While Nyota was prepping the medical bay, the enemy ship fired off a weak set of guns which broke the shields down. A few crew members were hurt from the impact\n");
      break;

    case 2:


    case 3:


    case 4:
      
      printf("While Nyota was protecting a crew member the enemy ship was able to charge another shot and fire upon the ship. This shot destroyed the whole ship\n");
      exit(1);
      break;

    case 5:
      printf("Putting yourself above the crew is a terrible way to think. You fail\n");
      exit(1);
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  mask |= (1 << 1);
  char member_name[8] = {0};

  printf("Who would you like to order third?\n");
  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (((mask & (1 << 1)) == 0) && !strncmp(member_name, "Nyota", 5)) {
    order_nyota_third(mask);
  } else if (((mask & (1 << 0)) == 0) && !strncmp(member_name, "Leonard", 7)) {
    order_leonard_third(mask);
  } else if (((mask & (1 << 2)) == 0) && !strncmp(member_name, "Scotty", 6)) {
    order_scotty_third(mask);
  } else if (((mask & (1 << 3)) == 0) && !strncmp(member_name, "Janice", 6)) {
    order_janice_third(mask);
  } else {
    printf("Seriously? Are you senile or something?\n");
    exit(-1);
  }
}

void order_leonard_second(unsigned int mask) {
  char choice = 0;

  printf("What would you like Leonard to do?\n");
  printf("[1] Lock onto the enemy ship for increased accuracy later\n");
  printf("[2] Charge phaser beams\n");
  printf("[3] Fire weak guns\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("After Leonard locked onto the enemy ship, they fired off another volley which destroyed the ship. Everyone died");
      exit(1);
      break;

    case 2:
      printf("While Leonard charged the phaser beams, the enemy ship fired off a more powerful shot which destroyed the ship.");
      exit(1);
      break;

    case 3:
      printf("The weak guns were able to miraculously disable the enemy ships guns with a lucky shot\n");
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  mask |= (1 << 0);
  char member_name[8] = {0};

  printf("Who would you like to order last?\n");
  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (((mask & (1 << 1)) == 0) && !strncmp(member_name, "Nyota", 5)) {
    order_nyota_third(mask);
  } else if (((mask & (1 << 0)) == 0) && !strncmp(member_name, "Leonard", 7)) {
    order_leonard_third(mask);
  } else if (((mask & (1 << 2)) == 0) && !strncmp(member_name, "Scotty", 6)) {
    order_scotty_third(mask);
  } else if (((mask & (1 << 3)) == 0) && !strncmp(member_name, "Janice", 6)) {
    order_janice_third(mask);
  } else {
    printf("Seriously? Are you senile or something?\n");
    exit(-1);
  }
}

void order_scotty_second(unsigned int mask) {
  char choice = 0;

  printf("What would you like Scotty to do?\n");
  printf("[1] Divert energy from warp drive into shields\n");
  printf("[2] Divert energy from shields into guns\n");
  printf("[3] Divert energy from shields into warp drive\n");
  printf("[4] Divert energy from guns into shields\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("With the additional power from the warp drive the ship survived a second volley from the enemy ship, but the shields are totally down now. It also seems that the enemy ships guns have overheated and will not be usable for a bit.\n");
      break;

    case 2:

    case 3:
      printf("Scotty powered down the shields by diverting energy away from it and so the second strike from the enemy ship destroyed the ship. Everyone died\n");
      exit(1);
      break;

    case 4:
      printf("With the additional power from the guns the ship survived a second volley from the enemy ship, but the shields are totally down now. It also seems that the enemy ships guns have overheated and will not be usable for some time.\n");
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  mask |= (1 << 2);
  char member_name[8] = {0};

  printf("Who would you like to order third?\n");
  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (((mask & (1 << 1)) == 0) && !strncmp(member_name, "Nyota", 5)) {
    order_nyota_third(mask);
  } else if (((mask & (1 << 0)) == 0) && !strncmp(member_name, "Leonard", 7)) {
    order_leonard_third(mask);
  } else if (((mask & (1 << 2)) == 0) && !strncmp(member_name, "Scotty", 6)) {
    order_scotty_third(mask);
  } else if (((mask & (1 << 3)) == 0) && !strncmp(member_name, "Janice", 6)) {
    order_janice_third(mask);
  } else {
    printf("Seriously? Are you senile or something?\n");
    exit(-1);
  }
}

void order_janice_second(unsigned int mask) {
  char choice = 0;

  printf("What would you like Janice to do?\n");
  printf("[1] Cry in the corner\n");
  printf("[2] Run around screaming\n");
  printf("[3] Hug Nyota for comfort\n");
  printf("[4] Fire off the guns which Janice hasn't been trained on yet\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("Janice managed to cry in the corner loud enough to not hear the ship get hit with another volley. The shields are completely down, but the enemy guns have overheated from firing too often. They will be unusable for a bit.\n");
      break;

    case 2:
      printf("After running around screaming, Leonard shot Janice right between the eyes. You don't have enough control over your crew, you fail\n");
      exit(1);

    case 3:
      printf("Nyota begrudgingly holds you as you wimper. Both of you fall to the floor after the second volley strikes the shields and then a few shots hit the ship. The shields are completely down, but the enemy ships guns have overheated and cannot be fired for a while\n");
      break;

    case 4:
      printf("Janice knows absolutely nothing about these guns and saw a ship in her sights when she got to it. She immediately fired only to realize that it was another part of her own ship. Everyone died from the whole in the ship.\n");
      exit(1);

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  mask |= (1 << 3);
  char member_name[8] = {0};

  printf("Who would you like to order third?\n");
  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (((mask & (1 << 1)) == 0) && !strncmp(member_name, "Nyota", 5)) {
    order_nyota_third(mask);
  } else if (((mask & (1 << 0)) == 0) && !strncmp(member_name, "Leonard", 7)) {
    order_leonard_third(mask);
  } else if (((mask & (1 << 2)) == 0) && !strncmp(member_name, "Scotty", 6)) {
    order_scotty_third(mask);
  } else if (((mask & (1 << 3)) == 0) && !strncmp(member_name, "Janice", 6)) {
    order_janice_third(mask);
  } else {
    printf("Seriously? Are you senile or something?\n");
    exit(-1);
  }
}

void order_nyota_third(unsigned int mask) {
  char choice = 0;

  printf("What would you like Nyota to do?\n");
  printf("[1] Tend to those in the medical bay\n");
  printf("[2] Protect Scotty\n");
  printf("[3] Protect Leonard\n");
  printf("[4] Protect Janice\n");
  printf("[5] Protect yourself (Kirk)\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("Nyota was able to stabalize everyone in the medical bay, but the enemy ship is preparing to beam a boarding crew onto the ship\n");
      break;

    case 2:


    case 3:


    case 4:
      
      printf("Nyota was able to stabalize them, but the enemy ship is preparing to beam a boarding crew onto the ship\n");
      break;

    case 5:
      printf("Putting yourself above the crew is a terrible way to think. You fail\n");
      exit(1);
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  mask |= (1 << 1);
  char member_name[8] = {0};

  printf("Who would you like to order last?\n");
  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (((mask & (1 << 1)) == 0) && !strncmp(member_name, "Nyota", 5)) {
    order_nyota_fourth(mask);
  } else if (((mask & (1 << 0)) == 0) && !strncmp(member_name, "Leonard", 7)) {
    order_leonard_fourth(mask);
  } else if (((mask & (1 << 2)) == 0) && !strncmp(member_name, "Scotty", 6)) {
    order_scotty_fourth(mask);
  } else if (((mask & (1 << 3)) == 0) && !strncmp(member_name, "Janice", 6)) {
    order_janice_fourth(mask);
  } else {
    printf("Seriously? Are you senile or something?\n");
    exit(-1);
  }
}

void order_leonard_third(unsigned int arg_mask) {
  char choice = 0;

  printf("What would you like Leonard to do?\n");
  printf("[1] Lock onto the enemy ship for increased accuracy later\n");
  printf("[2] Charge phaser beams\n");
  printf("[3] Fire weak guns\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("After Leonard locked onto the enemy ship, they got ready to send a boarding crew onto the ship\n");
      break;

    case 2:
      printf("While Leonard charged the phaser beams, the enemy ship got a boarding crew prepared and is ready to board the ship\n");
      break;

    case 3:
      printf("The weak guns pissed off the enemy so much that they are sending a boarding crew\n");
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  struct {
    char member_name[8];
    unsigned int mask;
  } ordering;

  ordering.mask = arg_mask | (1 << 0);

  my_fgets(ordering.member_name, sizeof(ordering.member_name) + sizeof(ordering.mask), stdin);
  ordering.member_name[sizeof(ordering.member_name) - 1] = 0;

  if (((ordering.mask & (1 << 1)) == 0) && !strncmp(ordering.member_name, "Nyota", 5)) {
    order_nyota_fourth(ordering.mask);
  } else if (((ordering.mask & (1 << 0)) == 0) && !strncmp(ordering.member_name, "Leonard", 7)) {
    order_leonard_fourth(ordering.mask);
  } else if (((ordering.mask & (1 << 2)) == 0) && !strncmp(ordering.member_name, "Scotty", 6)) {
    order_scotty_fourth(ordering.mask);
  } else if (((ordering.mask & (1 << 3)) == 0) && !strncmp(ordering.member_name, "Janice", 6)) {
    order_janice_fourth(ordering.mask);
  } else {
    printf("Seriously? Are you senile or something?\n");
    exit(-1);
  }
}

void order_scotty_third(unsigned int mask) {
  char choice = 0;

  printf("What would you like Scotty to do?\n");
  printf("[1] Divert energy from warp drive into shields\n");
  printf("[2] Divert energy from shields into guns\n");
  printf("[3] Divert energy from shields into warp drive\n");
  printf("[4] Divert energy from guns into shields\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:

    case 2:

    case 3:

    case 4:
      printf("The additional power did nothing becuase the enemy cannot fire right now. They prepared a boarding crew which will be beamed aboard soon\n");
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  mask |= (1 << 2);
  char member_name[8] = {0};

  printf("Who would you like to order last?\n");
  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (((mask & (1 << 1)) == 0) && !strncmp(member_name, "Nyota", 5)) {
    order_nyota_fourth(mask);
  } else if (((mask & (1 << 0)) == 0) && !strncmp(member_name, "Leonard", 7)) {
    order_leonard_fourth(mask);
  } else if (((mask & (1 << 2)) == 0) && !strncmp(member_name, "Scotty", 6)) {
    order_scotty_fourth(mask);
  } else if (((mask & (1 << 3)) == 0) && !strncmp(member_name, "Janice", 6)) {
    order_janice_fourth(mask);
  } else {
    printf("Seriously? Are you senile or something?\n");
    exit(-1);
  }
}

void order_janice_third(unsigned int mask) {
  char choice = 0;

  printf("What would you like Janice to do?\n");
  printf("[1] Cry in the corner\n");
  printf("[2] Run around screaming\n");
  printf("[3] Hug Nyota for comfort\n");
  printf("[4] Fire off the guns which Janice hasn't been trained on yet\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("Janice managed to cry in the corner loud enough to make the enemy want to board the ship and kill her to stop the noise. The boarding crew is coming soon\n");
      break;

    case 2:
      printf("After running around screaming, Leonard shot Janice right between the eyes. You don't have enough control over your crew, you fail\n");
      exit(1);

    case 3:
      printf("You distracted Nyota while she was tending to the injured which caused her to kill a fellow crew member. You fail\n");
      exit(1);
      break;

    case 4:
      printf("Janice knows absolutely nothing about these guns and saw a ship in her sights when she got to it. She immediately fired only to realize that it was another part of her own ship. Everyone died from the whole in the ship.\n");
      exit(1);

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  mask |= (1 << 3);
  char member_name[8] = {0};

  printf("Who would you like to order last?\n");
  my_fgets(member_name, sizeof(member_name) - 1, stdin);
  member_name[sizeof(member_name) - 1] = 0;

  if (((mask & (1 << 1)) == 0) && !strncmp(member_name, "Nyota", 5)) {
    order_nyota_fourth(mask);
  } else if (((mask & (1 << 0)) == 0) && !strncmp(member_name, "Leonard", 7)) {
    order_leonard_fourth(mask);
  } else if (((mask & (1 << 2)) == 0) && !strncmp(member_name, "Scotty", 6)) {
    order_scotty_fourth(mask);
  } else if (((mask & (1 << 3)) == 0) && !strncmp(member_name, "Janice", 6)) {
    order_janice_fourth(mask);
  } else {
    printf("Seriously? Are you senile or something?\n");
    exit(-1);
  }
}

void order_nyota_fourth(unsigned int mask) {
  (void)(mask);

  char choice = 0;

  printf("What would you like Nyota to do?\n");
  printf("[1] Tend to those in the medical bay\n");
  printf("[2] Protect Scotty\n");
  printf("[3] Protect Leonard\n");
  printf("[4] Protect Janice\n");
  printf("[5] Protect yourself (Kirk)\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:

    case 2:

    case 3:

    case 4:
      printf("Nyota stabalized everyone in the medical bay and sealed the doors. The enemy boarding crew got into the ship and has you at gunpoint\n");
      break;

    case 5:
      printf("Putting yourself above the crew is a terrible way to think. You fail\n");
      exit(1);
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  printf("Do you have any final words?\n");
  char death_message[16] = {0};
  my_fgets(death_message, 15, stdin);

  printf("Everyone laughs as you say \"%s\", then you all die\n", death_message);


  exit(-1);
}

void order_leonard_fourth(unsigned int mask) {
  (void)(mask);
  
  printf("Everything is dark. The enemy ship has beamed a boarding crew aboard and there is nothing for you to do. They have released gas in the ship and you are becoming incoherent.");
  printf("Do you have any dying words?\n");

  char death_message[20] = {0};
  my_fgets(death_message, 19, stdin);

  // NOTE: Vuln 2 here
  printf(death_message);
  
  exit(-1);
}

void order_scotty_fourth(unsigned int mask) {
  (void)(mask);
  
  char choice = 0;

  printf("What would you like Scotty to do?\n");
  printf("[1] Divert energy from warp drive into shields\n");
  printf("[2] Divert energy from shields into guns\n");
  printf("[3] Divert energy from shields into warp drive\n");
  printf("[4] Divert energy from guns into shields\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:

    case 2:

    case 3:

    case 4:
      printf("The additional power did nothing becuase the enemy has already boarded the ship. They have their guns pointed and are ready to fire\n");
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  printf("Do you have any final words?\n");
  char death_message[16] = {0};
  my_fgets(death_message, 15, stdin);
  printf("The enemy laughs as you say \"%s\", and then they blow your head off\n", death_message);
  exit(-1);
}

void order_janice_fourth(unsigned int mask) {
  (void)(mask);

  char choice = 0;

  printf("What would you like Janice to do?\n");
  printf("[1] Cry in the corner\n");
  printf("[2] Run around screaming\n");
  printf("[3] Hug Nyota for comfort\n");
  printf("[4] Fire off the guns which Janice hasn't been trained on yet\n");

  my_fgets(&choice, 1, stdin);
  choice -= 0x30;

  printf("\n");

  switch (choice) {
    case 1:
      printf("The enemy boarding crew found and silenced Janice. They now have their knives on your throat\n");
      break;

    case 2:
      printf("After running around screaming, Leonard shot Janice right between the eyes. You don't have enough control over your crew, you fail\n");
      exit(1);

    case 3:
      printf("You distracted Nyota while she was tending to the injured which caused her to kill a fellow crew member. You fail\n");
      exit(1);
      break;

    case 4:
      printf("Janice knows absolutely nothing about these guns and saw a ship in her sights when she got to it. She immediately fired and actually destroyed the enemy ship! As everyone celebrated they quickly realized that the blast from destroying the enemy ship's fuel cell is coming back and will destroy the ship.\n");
      break;

    default:
      printf("You are not fit to be a captain given you can't even make a decision. You literally only had to type one character. Pathetic\n");
      exit(1);
  }

  printf("\n\n");

  printf("Do you have any final words?\n");
  char death_message[16] = {0};
  my_fgets(death_message, 15, stdin);
  printf("The enemies laugh as you say \"%s\", then kill you\n", death_message);
  exit(-1);
}
