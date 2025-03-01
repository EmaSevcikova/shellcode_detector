#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[128];
    strcpy(buffer, input);  // No bounds checking
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    printf("Done.\n");
    return 0;
}