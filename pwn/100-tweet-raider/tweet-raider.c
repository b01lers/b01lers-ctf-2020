#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>

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

int calculateScore(char * tweet, int * score) {
    char * tweet_ptr = tweet;
    for ( ; *tweet; ++tweet) *tweet = tolower(*tweet);
    tweet = tweet_ptr;

    int i = 0;
    while(tweet[i]) {
        // TODO: Add more words
        if(strncmp(tweet+i, "space", 5) == 0) (*score)++;
        if(strncmp(tweet+i, "rocket", 6) == 0) (*score)++;
        if(strncmp(tweet+i, "electric", 8) == 0) (*score)++;
        if(strncmp(tweet+i, "fast", 4) == 0) (*score)++;
        if(strncmp(tweet+i, "dank", 4) == 0) (*score)++;
        if(strncmp(tweet+i, "dope", 4) == 0) (*score)++;
        if(strncmp(tweet+i, "420", 3) == 0) (*score)++;
        if(strncmp(tweet+i, "lit", 3) == 0) (*score)++;
        if(strncmp(tweet+i, "cybertruck", 10) == 0) (*score)++;
        if(strncmp(tweet+i, "cyber", 5) == 0) (*score)++;
        if(strncmp(tweet+i, "truck", 5) == 0) (*score)++;
        if(strncmp(tweet+i, "tesla", 5) == 0) (*score)++;
        if(strncmp(tweet+i, "boring", 6) == 0) (*score)++;
        if(strncmp(tweet+i, "tunnel", 6) == 0) (*score)++;
        if(strncmp(tweet+i, "flamethrower", 12) == 0) (*score)++;
        if(strncmp(tweet+i, "meme", 4) == 0) (*score)++;
        i++;
    }
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    char tweet[281];
    int * score = malloc(sizeof(int));
    *score = 0;

    printf("Welcome to Mlon Eusk's Tweet Rater!\nInput your tweet, and we will give you a rating.\n\n");

    printf("Tweet: ");
    fgets(tweet, 280, stdin);
    printf("Your tweet:\n");
    printf(tweet);

    calculateScore(tweet, score);
    printf("Your score: %d\n", *score);
    if(*score > 9000) {
        printf("Your score is over 9000!\n");
        printf("%s\n", readFile("./flag.txt"));
    }
}
