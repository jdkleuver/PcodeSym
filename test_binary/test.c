#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 32

void win(char * password) {
    printf("you win: %s\n", password);
}

void lose(int where) {
    printf("you lose: %d\n", where);
    exit(1);
}

void start(char *password) {
    if(password[4] != 'A') {
        lose(1);
    }

    if(strlen(password) != 8) {
        lose(2);
    }

    if(strncmp(password, "easy", 4) != 0) {
        lose(3);
    }

    if(strstr(password, "pie") == NULL) {
        lose(4);
    }

    win(password);
    return;
}

int main(int argc, char *argv[]){
    if(argc != 2) {
        printf("usage: %s PASSWORD\n", argv[0]);
        exit(1);
    }

    char password[BUF_SIZE] = {0};
    strncpy(password, argv[1], BUF_SIZE);
    password[BUF_SIZE-1] = '\0';
    start(password);
    return 0;
}
