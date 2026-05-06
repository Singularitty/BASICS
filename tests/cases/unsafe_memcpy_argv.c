#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char buffer[8];
    const char *input = argc > 1 ? argv[1] : "AAAAAAAAAAAAAAAA";
    size_t n = argc > 2 ? (size_t)atoi(argv[2]) : 32;

    memcpy(buffer, input, n);
    puts(buffer);
    return 0;
}
