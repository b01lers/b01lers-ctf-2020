#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void memdump(FILE * fd, char * p , int len) {
    int i;
    fprintf(fd, "0x%016lX: ", (unsigned long) p); // Print address of the beginning of p. You need to print it every 16 bytes
    char asciis[16];
    for (i=0; i < len; i++) {
        if (i % 16 == 0 && i != 0 ) {
            fprintf(fd, " ");
            for(int j = 0; j < 16; j++) {
                fprintf(fd, "%c", asciis[j]);
            }
            fprintf(fd,"\n");
            fprintf(fd, "0x%016lX: ", (unsigned long) p + i); // Print address of the beginning of p. You need to print it every 16 bytes
        }
        int c = p[i]&0xFF; // Get value at [p]. The &0xFF is to make sure you truncate to 8bits or one byte.

        // Print first byte as hexadecimal
        fprintf(fd, "%02X ", c);

        // Print first byte as character. Only print characters >= 32 that are the printable characters.
        asciis[i % 16] = (c>=32&&c<127)?c:'.';

    }
    if(i % 16 == 0) {
        fprintf(fd, " ");
        for(int j = 0; j < 16; j++) {
            fprintf(fd, "%c", asciis[j]);
        }
    } else {
        for(int j = 0; j < 16 - (i % 16); j++) {
            fprintf(fd, "   ");
        }
        fprintf(fd, " ");
        for(int j = 0; j < i % 16; j++) {
            fprintf(fd, "%c", asciis[j]);
        }
    }
    fprintf(fd,"\n");
}

void smemdump(char * fd, char * p , int len) {
    int i;
    memset(fd, '\0', len);
    sprintf(fd + strlen(fd), "0x%016lX: ", (unsigned long) p); // Print address of the beginning of p. You need to print it every 16 bytes
    char asciis[16];
    for (i=0; i < len; i++) {
        if (i % 16 == 0 && i != 0 ) {
            sprintf(fd + strlen(fd), " ");
            for(int j = 0; j < 16; j++) {
                sprintf(fd + strlen(fd), "%c", asciis[j]);
            }
            sprintf(fd + strlen(fd),"\n");
            sprintf(fd + strlen(fd), "0x%016lX: ", (unsigned long) p + i); // Print address of the beginning of p. You need to print it every 16 bytes
        }
        int c = p[i]&0xFF; // Get value at [p]. The &0xFF is to make sure you truncate to 8bits or one byte.

        // Print first byte as hexadecimal
        sprintf(fd + strlen(fd), "%02X ", c);

        // Print first byte as character. Only print characters >= 32 that are the printable characters.
        asciis[i % 16] = (c>=32&&c<127)?c:'.';

    }
    if(i % 16 == 0) {
        sprintf(fd + strlen(fd), " ");
        for(int j = 0; j < 16; j++) {
            sprintf(fd + strlen(fd), "%c", asciis[j]);
        }
    } else {
        for(int j = 0; j < 16 - (i % 16); j++) {
            sprintf(fd + strlen(fd), "   ");
        }
        sprintf(fd + strlen(fd), " ");
        for(int j = 0; j < i % 16; j++) {
            sprintf(fd + strlen(fd), "%c", asciis[j]);
        }
    }
    sprintf(fd + strlen(fd),"\n\x00");
}
