#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

int percent_complete = 50;
int throttle = 10;
char * reward = "Sorry, you died!";

char * readFile(char * f) {
    int c;
    FILE *file;
    file = fopen(f, "r");
    char * str = malloc(51);
    if(file) {
        int i = 0;
        while((c = getc(file)) != EOF) {
            str[i] = c;
            i++;
            if(i >= 50) {
                break;
            }
        }
        str[i] = '\0';
        fclose(file);
    }
    return str;
}


void clear() {
    printf("\e[1;1H\e[2J");
}

int suck_power() {
    return (100 - percent_complete) / 5;
}

void draw() {
    clear();
    if(throttle == 10) {
        printf("Throttle: MAX\n");
    } else {
        printf("Throttle: %d\n", throttle);
    }
    printf("Gravity: %d\n", suck_power());

    int i = 0;
    printf("O");
    while(i < percent_complete / 2) {
        printf(" ");
        i++;
    }
    printf("=>");
    i += 2;
    while(i < 100 / 2) {
        printf(" ");
        i++;
    }
    printf("|\n");
}

void accelerate(char * value) {
    if(throttle < 10) {
        throttle += 1;
    }
}

void decelerate(char * value) {
    if(throttle > 0) {
        throttle -= 1;
    }
}

void step() {
    printf("> ");
    char * line = NULL;
    size_t size;
    if (getline(&line, &size, stdin) == -1) {
        exit(0);
    }
    strtok(line, "\n ");
    char * arg1 = line;
    char * arg2 = strtok(NULL, "\n ");
    if (arg1[0] == 'a') {
        accelerate(arg2);
    }
    if (arg1[0] == 'd') {
        decelerate(arg2);
    }

    free(line);
}

void update() {
    percent_complete -= suck_power();
    percent_complete += throttle;
}

void lose(char * player) {
    printf("You lose %s!\n", player);
    puts(reward);
}

void win(char * player) {
    printf("You win, %s!\n", player);
    readFile("./flag.txt");
}


int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    printf("Captain's Name: ");
    int i = 0;
    char player[128];
    read(0, player+i, 1);
    while(player[i] != '\n') {
        i++;
        read(0, player+i, 1);
    }
    player[i] = '\x00';
    printf("Welcome, %s!\n", player);

    while(percent_complete > 0 && percent_complete < 100) {
        draw();
        step();
        update();
    }
    if(percent_complete <= 0) {
        lose(player);
    } else if(percent_complete >= 100) {
        win(player);
    }
}
