// compile with   gcc -shared -o mylib.so -fPIC mylib.c

#include <stdio.h>

/* disable sleep, usleep, and fix a given time in gettimeofday */

unsigned int sleep(unsigned int seconds) {  return 0; }  // DISABLE

int usleep(unsigned int usec) { return 0; }         // DISABLE


struct timeval {
   unsigned long int tv_sec;     /* seconds */
   unsigned long int tv_usec;    /* microseconds */  
};

int gettimeofday(struct timeval *tv, struct timeval * tz) {    // FIXED time
   tv->tv_sec = 1234567; 
   tv->tv_usec = 0; 
   return 0;
}

/* OVERRIDE rand() */

int rand() {
    FILE* f = fopen("rand_result.dat", "r");
    int res;
    fscanf(f, "%d", &res);
    fclose(f);
    //printf("%d\n", res);
    fflush(stdout);
    return res;
} // FIXED answer


/* EOF */
