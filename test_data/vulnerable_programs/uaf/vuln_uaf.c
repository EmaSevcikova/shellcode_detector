#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input) {
    char *buffer = (char *)malloc(128);
    free(buffer);
    strcpy(buffer, input);  // Use after free
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