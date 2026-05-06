#include <stdio.h>

int main(void) {
    char buffer[8];

    for (int i = 0; i < 16; i++) {
        buffer[i] = 'A';
    }

    puts(buffer);
    return 0;
}
