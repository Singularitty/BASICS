#include <stdio.h>

int main(int argc, char **argv) {
    char buffer[8];
    const char *input = argc > 1 ? argv[1] : "AAAAAAAAAAAAAAAA";

    sprintf(buffer, "%s", input);
    puts(buffer);
    return 0;
}
