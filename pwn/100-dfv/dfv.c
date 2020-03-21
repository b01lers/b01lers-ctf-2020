#include<stdio.h>
#include<stdlib.h>
#include<string.h>
//
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

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    long mask2 = 0x1052949205934052;
    long liscense;
    long mask = 0x005641444c4f4f43 ^ mask2; // THANKS DAVE

    printf("Dave has ruined our system. He updated the code, and now he even has trouble checking his own liscense!\n");
    printf("If you can please make it work, we'll reward you!\n\n");

    printf("Welcome to the Department of Flying Vehicles.\n");
    printf("Which liscense plate would you like to examine?\n > ");
    gets((char*)&liscense);

    if((liscense ^ mask ^ mask2) != 0) {
        printf("Error.\n"); // THANKS DAVE
    } else {
        if(strncmp((char*)&liscense, "COOLDAV\x00", 8) != 0) {
            printf("Thank you so much! Here's your reward!\n%s", readFile("flag.txt"));
        } else {
            printf("Hi Dave!\n");
        }
    }
}
