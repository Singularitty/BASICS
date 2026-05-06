#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buffer[16];
    const char *input = argc > 1 ? argv[1] : "hello";

    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    puts(buffer);
    return 0;
}
