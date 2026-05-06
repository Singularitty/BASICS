#include <stdio.h>

int main(void) {
    char buffer[8];

    for (int i = 0; i <= 8; i++) {
        buffer[i] = 'B';
    }

    puts(buffer);
    return 0;
}
