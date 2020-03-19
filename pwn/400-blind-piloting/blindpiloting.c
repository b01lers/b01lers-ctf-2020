#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

void getInput() {
    int i = 0;
    char c;
    char buf[8];
    write(1, "> ", 2);
    while(1) {
        //if (c == '\x00') continue;
        read(0, &c, 1);
        if (c == '\n' || i == 64) break;
        buf[i] = c;
        i++;
    }
}

void win() {
    system("cat flag1.txt");
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    int pid;
    while(1) {
        pid = fork();
        if(pid == 0) {
            // CHILD
            getInput();
            exit(0);
        }
        else if (pid > 0) {
            // PARENT
            waitpid(pid, NULL, 0);
        }
        else {
            // ERROR
            perror("wat");
        }
    }
}
