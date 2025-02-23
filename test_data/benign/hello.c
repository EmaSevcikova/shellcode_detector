#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("Hello, World!\n");

    // Print the process ID for debugging
    printf("PID: %d\n", getpid());

    // Pause execution to allow debugger attachment
    printf("Waiting for debugger...\n");
    getchar();  // Press Enter to continue execution

    return 0;
}
