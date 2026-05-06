#include <stdio.h>

extern char *gets(char *);

int main(void) {
    char buffer[8];

    gets(buffer);
    puts(buffer);
    return 0;
}
