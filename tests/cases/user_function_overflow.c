#include <stdio.h>
#include <string.h>

void copy_into_local(const char *input) {
    char buffer[8];
    strcpy(buffer, input);
    puts(buffer);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 0;
    }

    copy_into_local(argv[1]);
    return 0;
}
