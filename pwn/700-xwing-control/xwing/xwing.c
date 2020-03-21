#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<unistd.h>
#include "memdump.h"

#define MAX_ENEMIES 8

char * PASSWORD = "LeiaIsCute";
int failed_logins = 0;
int gameOver = 0;

int attemptedFix = 0;
int speed = 10;
int hp = 1000;
int excellentHp = 700;
int goodHp = 300;
int criticalHp = 0;
int damage = 10;
int distance = 10000000;
char * shipEngine;
char * hyperdriveStatus = "Off";

char * outputMessage = NULL;
int outputMessageMalloced = 0;

int lastTime = 0;

int maxNoHyperdriveSpeed = 100;
int maxHyperdriveSpeed = 1000000;

void updateStats() {
    int curTime = time(0);
    distance -= (curTime - lastTime) * speed;
    lastTime = curTime;
    if(distance <= 0) {
        speed = 0;
        distance = 0;
    }
}

void waitforenter() {
    char * line = NULL;
    size_t size;
    if (getline(&line, &size, stdin) == -1) {
        exit(0);
    }
    free(line);
}

void clear() {
    printf("\e[1;1H\e[2J");
}

char * getShipStatus() {
    if(strcmp(shipEngine, "RW5naW5lIEludGFjdC4") == 0) {
        if(hp > excellentHp) {
            return "Excellent";
        }
        if(hp > goodHp) {
            return "Good";
        }
        if(hp > criticalHp) {
            return "Critical";
        }
    } else {
        return "Critical";
    }
}

void printShipStatus() {
    updateStats();
    printf("\033[32;1;4mX-Wing Control Panel\033[0m\n");
    printf("\033[31mUser:\t\t\t\033[34m Luke Skywalker\n");
    printf("\033[31mDroid:\t\t\t\033[34m R2-D2\n");
    printf("\033[31mCallsign:\t\t\033[34m Red 5\n");
    printf("\033[31mShip Status:\t\t\033[34m %s\n", getShipStatus());
    printf("\033[31mDestination:\t\t\033[34m Death Star\n");
    printf("\033[31mDistance Remaining:\t\033[34m %d\n", distance);
    printf("\033[31mSpeed:\t\t\t\033[34m %d\n", speed);
    printf("\033[31mHyperdrive:\t\t\033[34m %s\n", hyperdriveStatus);

    printf("\033[0m");
}

void destroyEngine() {
    shipEngine[4] = '#';
}

void setupEngine() {
    lastTime = time(0);
    shipEngine = malloc(30);
    strcpy(shipEngine, "RW5naW5lIEludGFjdC4");
}

/*********************************************************************
 * Shop Control Methods                                              *
 *********************************************************************/

void throttle(char * arg) {
    outputMessage = "Throttle set.";
    int newSpeed = 0;
    sscanf(arg, "%d", &newSpeed);
    if(newSpeed < 0) {
        outputMessage = "\033[33;1mShip Malfunction.\033[0m";
        shipEngine[12] = '#';
        return;
    }
    if(newSpeed > maxHyperdriveSpeed) {
        outputMessage = "\033[33;1mError: Impossibly fast speed.\033[0m";
        return;
    }
    if(strcmp(hyperdriveStatus, "Off") == 0) {
        if(newSpeed > maxNoHyperdriveSpeed) {
            outputMessage = "\033[33;1mError: Too fast to travel with hyperdrive disabled.\033[0m";
            return;
        }
    }
    speed = newSpeed;
}

void hyperdrive(char * arg) {
    if(strcmp(getShipStatus(), "Excellent") != 0) {
        outputMessage = "\033[33;1mShip Malfunction.\033[0m";
        shipEngine[10] = '#';
        return;
    }

    if(strcmp(arg, "on") == 0) {
        hyperdriveStatus = "On";
        outputMessage = "Hyperdrive Enabled.";
    } else {
        hyperdriveStatus = "Off";
        outputMessage = "Hyperdrive Disabled.";
    }
}

void help() {
    outputMessage = "X-Wing Advanced Control Interface.";
}

void examine(char * arg1, char * arg2) {
    int len;
    void * p;
    sscanf(arg1, "%p", &p);
    sscanf(arg2, "%d", &len);

    outputMessage = malloc(0x40000);
    outputMessageMalloced = 1;
    smemdump(outputMessage, p, len);
}

void fix(char * arg1, char * arg2) {
    if(attemptedFix) {
        outputMessage = "\033[33;1mShip Malfunction. Fix impossible.\033[0m";
        return;
    }
    long val;
    void * p;
    sscanf(arg1, "%p", &p);
    sscanf(arg2, "%p", &val);

    if((void*)&arg1 - 100000 < (void*)p && (void*)&arg1 + 100000 > (void*)p) {
        outputMessage = "\033[33;1mShip Malfunction. Fix impossible.\033[0m";
        return;
    }

    *(long*)p = val;

    attemptedFix = 1;
}

/*********************************************************************
 * Battle Methods                                                    *
 *********************************************************************/
typedef struct Enemy {
    /*no*/ char * name;
    int hp;
    int damage;
    int idx;
    int operational;
} Enemy;

Enemy * enemies[MAX_ENEMIES];

Enemy * currentTarget = NULL;

Enemy * deathStar;

Enemy * createEnemy(char * name, int hp, int damage) {
    int found = 0;
    int i;
    for(i = 0; i < MAX_ENEMIES; i++) {
        if(enemies[i] == NULL) {
            found = 1;
            break;
        }
    }
    if(!found) return NULL;

    Enemy * enemy = malloc(sizeof(Enemy));
    enemy->name = name;
    enemy->hp = hp;
    enemy->damage = damage;
    enemy->idx = i;
    enemy->operational = 1;

    enemies[i] = enemy;

    return enemy;
}

void freeEnemy(int i) {
    free(enemies[i]);
    enemies[i] = NULL;
}

void printBattleStatus() {
    updateStats();
    printf("\033[32;1;4mX-Wing Control Panel\033[0m\n");
    printf("\033[31mUser:\t\t\t\033[34m Luke Skywalker\n");
    printf("\033[31mDroid:\t\t\t\033[34m R2-D2\n");
    printf("\033[31mCallsign:\t\t\033[34m Red 5\n");
    printf("\033[31mShip Status:\t\t\033[34m %s\n", getShipStatus());
    printf("\033[31mEnemies:\t\t\033[34m\n");
    int no_enemies = 1;
    for(int i = 0; i < MAX_ENEMIES; i++) {
        if(enemies[i] != NULL) {
            printf("\t%d:\t%s\n", i, enemies[i]->name);
            no_enemies = 0;
        }
    }
    if(no_enemies) {
        printf("\tNone\n");
    }

    if(currentTarget) {
        printf("\033[31mTarget:\t\t\033[34m\n\tName: %s\n\tHP: %d\n\tDamage: %d\n", currentTarget->name, currentTarget->hp, currentTarget->damage);
    } else {
        printf("\033[31mTarget:\t\t\033[34m %s\n", "None");
    }
    if(deathStar->operational) {
        printf("\033[31mDeath Star Status:\t\033[34m %s\n", "Fully Operational");
    } else {
        printf("\033[31mDeath Star Status:\t\033[34m %s\n", "Nearly Operational");
    }

    printf("\033[0m");
}

void performAttacks() {
    for(int i = 0; i < MAX_ENEMIES; i++) {
        if(enemies[i] != NULL && enemies[i]->operational) {
            hp -= enemies[i]->damage;
        }
    }
}

void target(char * arg1) {
    outputMessage = "Targeting.";
    int i = atoi(arg1);
    currentTarget = enemies[i];
}

void attack(char * arg1, char * arg2) {
    if(currentTarget != NULL) {
        outputMessage = "Attacking";
        currentTarget->hp -= damage;
        if(currentTarget->hp <= 0) {
            if(deathStar == currentTarget) {
                outputMessage = "You have defeated the death star. You win.";
                gameOver = 1;
            }
            freeEnemy(currentTarget->idx);
            currentTarget = NULL;
        }
    } else {
        outputMessage = "Missed. No target.";
    }
}

/*********************************************************************
 * Main Methods                                                      *
 *********************************************************************/

int login() {
    // Asks for password to continue, exits if the password is incorrect.
    clear();
    printf("\033[32;1;4mX-Wing Control Panel\033[0m\n");
    printf("\033[31mUser:\t\t\t\033[34m Luke Skywalker\n");
    printf("\033[31mDroid:\t\t\t\033[34m R2-D2\n");
    printf("\033[31mPermission Level:\t\033[34m None\n");
    printf("\n");
    char * passwd = getpass("\033[33;1mAuthorization Required:\033[0m ");


    if(strcmp(passwd, PASSWORD)) {
        failed_logins++;
        printf("Unauthorized. Failure #%d\n", failed_logins);
        if(failed_logins >= 3) {
            clear();
            printf("\033[33;1mThree failed authorization attempts. Shutting Down....\033[0m\n");
            exit(0);
        }
        login();
    }
}

int fly() {
    while(distance != 0) {
        clear();
        printShipStatus();
        if(outputMessage) {
            printf("\n%s\n", outputMessage);
            if(outputMessageMalloced) {
                free(outputMessage);
                outputMessageMalloced = 0;
            }
            outputMessage = NULL;
        }
        printf("\n\033[36m>\033[0m ");
        char * line = NULL;
        size_t size;
        if (getline(&line, &size, stdin) == -1) {
            exit(0);
        }

        strtok(line, "\n ");
        char * arg1 = line;
        char * arg2 = strtok(NULL, "\n ");
        char * arg3 = strtok(NULL, "\n ");
        if (strcmp(arg1, "throttle") == 0) {
            throttle(arg2);
        } else if (strcmp(line, "hyperdrive") == 0) {
            hyperdrive(arg2);
        } else if (strcmp(line, "help") == 0) {
            help();
        } else if (strcmp(line, "examine") == 0) {
            examine(arg2, arg3);
        } else if (strcmp(line, "fix") == 0) {
            fix(arg2, arg3);
        } else if (strcmp(line, "exit") == 0) {
            exit(0);
        } else {
            outputMessage = "\033[33;1mCommand not found.\033[0m";
        }

        free(line);
    }
}

int fight() {
    clear();
    deathStar = createEnemy("Death Star", 10000000, 1000000);
    deathStar->operational = 0;
    createEnemy("Tie Fighter", 50, 10);
    createEnemy("Tie Fighter", 50, 10);
    createEnemy("Tie Fighter", 50, 10);
    createEnemy("Tie Fighter", 50, 10);
    createEnemy("Tie Fighter", 50, 10);
    currentTarget = deathStar;
    int count = 0;
    while(1) {
        clear();

        count++;
        if(count >= 8) {
            deathStar->operational = 1;
        }

        printBattleStatus();

        if(outputMessage) {
            printf("\n%s\n", outputMessage);
            if(outputMessageMalloced) {
                free(outputMessage);
                outputMessageMalloced = 0;
            }
            outputMessage = NULL;
        }

        if(hp <= 0) {
            exit(0);
        }
        if(gameOver) {
            break;
        }
        printf("\n\033[36m>\033[0m ");
        char * line = NULL;
        size_t size;
        if (getline(&line, &size, stdin) == -1) {
            exit(0);
        }

        strtok(line, "\n ");
        char * arg1 = line;
        char * arg2 = strtok(NULL, "\n ");
        char * arg3 = strtok(NULL, "\n ");
        if (strcmp(arg1, "target") == 0) {
            target(arg2);
        } else if (strcmp(line, "attack") == 0) {
            attack(arg2, arg3);
        } else if (strcmp(line, "help") == 0) {
            help();
        } else if (strcmp(line, "exit") == 0) {
            exit(0);
        } else {
            outputMessage = "\033[33;1mCommand not found.\033[0m";
        }

        performAttacks();
    }
}

void logwin() {
    for(int i = 0; i < MAX_ENEMIES; i++) {
        if(enemies[i] != NULL) {
            char * addr = malloc(24);
            printf("You have captured %s at %p. What would you like to rename it to? at %p\n", enemies[i]->name, enemies[i], addr);
            enemies[i]->name = addr;
            printf("\033[36m>\033[0m ");
            fgets(enemies[i]->name, 256, stdin);
        }
    }

    clear();
    printf("\033[32;1;4mX-Wing Control Panel\033[0m\n");
    printf("\033[31mUser:\t\t\t\033[34m Luke Skywalker\n");
    printf("\033[31mDroid:\t\t\t\033[34m R2-D2\n");
    printf("\033[31mCallsign:\t\t\033[34m Red 5\n");
    printf("\033[31mShip Status:\t\t\033[34m %s\n", getShipStatus());
    printf("\033[31mFleet:\t\t\033[34m\n");
    int no_enemies = 1;
    for(int i = 0; i < MAX_ENEMIES; i++) {
        if(enemies[i] != NULL) {
            printf("\t%d:\t%s\n", i, enemies[i]->name);
            no_enemies = 0;
        }
    }
    if(no_enemies) {
        printf("\tNone\n");
    }

    printf("\033[31mDeath Star Status:\t\033[34m %s\n", "Eliminated");

    printf("\033[0m\n");

    if(outputMessage) {
        printf("\n%s\n", outputMessage);
        if(outputMessageMalloced) {
            free(outputMessage);
            outputMessageMalloced = 0;
        }
        outputMessage = NULL;
    }
}

void cleanup() {
    for(int i = 0; i < MAX_ENEMIES; i++) {
        if(enemies[i] != NULL) {
            free(enemies[i]->name);
            free(enemies[i]);
            enemies[i] = NULL;
        }
    }
    free(shipEngine);
}

char * readFile(char * f) {
    int c;
    FILE *file;
    file = fopen(f, "r");
    char * str = malloc(201);
    if(file) {
        int i = 0;
        while((c = getc(file)) != EOF) {
            str[i] = c;
            i++;
            if(i >= 200) {
                break;
            }
        }
        str[i] = '\0';
        fclose(file);
    }
    return str;
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setupEngine();
    destroyEngine();
    updateStats();

    char * tmp;
    login();
    outputMessage = readFile("./flag1.txt");
    outputMessageMalloced = 1;
    fly();
    outputMessage = readFile("./flag2.txt");
    outputMessageMalloced = 1;
    fight();
    outputMessage = readFile("./flag3.txt");
    outputMessageMalloced = 1;
    logwin();
    cleanup();
}
