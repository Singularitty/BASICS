#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buffer[8];

    if (argc < 2) {
        return 0;
    }

    strcpy(buffer, argv[1]);
    puts(buffer);
    return 0;
}
