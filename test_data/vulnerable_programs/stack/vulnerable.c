#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input); // Buffer overflow vulnerabilit
}

int main() {
    char input[1024];
    printf("Enter payload: ");
    fflush(stdout);
    read(STDIN_FILENO, input, sizeof(input)); // Read input
    vulnerable_function(input); // Trigger vulnerability
    return 0;
}