#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input) {
    char *buffer = (char *)malloc(128);
    strcpy(buffer, input);  // No bounds checking
    free(buffer);
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