# arch_patterns.py
architecture_patterns = {
    "32bit": [
        bytes([0xcd, 0x80]),  # int 0x80 (32-bit syscall)
        bytes([0x89, 0xe3]),  # mov ebx, esp (common in 32-bit)
        bytes([0x31, 0xdb]),  # xor ebx, ebx (32-bit arg register)
        bytes([0x53]),  # push ebx (32-bit register)
        bytes([0x89, 0xe1]),  # mov ecx, esp (32-bit arg register)
        bytes([0x8d, 0x4c, 0x24]),  # lea ecx, [esp+X] (32-bit addressing)
        # Adding patterns from your second set
        bytes([0x31, 0xc9]),  # xor ecx, ecx (counter initialization)
        bytes([0xf7, 0xe1]),  # mul ecx (counter initialization)
        bytes([0x99]),         # cdq (clearing edx, often used in decoders)
        bytes([0x81, 0xf1]),   # xor ecx, immediate (setting counter)
        bytes([0x83, 0xf1]),   # xor ecx, small immediate (setting counter)
    ],
    "64bit": [
        bytes([0x0f, 0x05]),  # syscall (64-bit)
        bytes([0x48]),  # REX prefix for 64-bit operations
        bytes([0x48, 0x31, 0xff]),  # xor rdi, rdi (64-bit register)
        bytes([0x48, 0x89, 0xe7]),  # mov rdi, rsp (64-bit register)
        bytes([0x49]),  # REX prefix for r8-r15 registers
        # Adding patterns from your second set
        bytes([0x48, 0x31, 0xc9]),  # xor rcx, rcx (counter initialization)
        bytes([0x48, 0xf7, 0xe1]),  # mul rcx (counter initialization)
        bytes([0x48, 0x99]),        # cqo (clearing rdx, often used in decoders)
        bytes([0x48, 0x83, 0xf1]),  # xor rcx, small immediate (setting counter)
        bytes([0x48, 0x31, 0xff]),  # xor rdi, rdi (often register used for address)
    ]
}