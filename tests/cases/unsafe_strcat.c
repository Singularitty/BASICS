#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buffer[8] = "abc";
    const char *input = argc > 1 ? argv[1] : "AAAAAAAAAAAAAAAA";

    strcat(buffer, input);
    puts(buffer);
    return 0;
}
