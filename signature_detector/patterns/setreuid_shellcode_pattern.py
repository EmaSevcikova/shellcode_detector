name = "privilege escalation using setreuid(0,0)"
# Patterns for setreuid(0,0) shellcode detection
behavior_patterns = {
    "32bit": {
        "syscall": [
            bytes([0xcd, 0x80])  # int 0x80 (32-bit syscall)
        ],
        "setreuid_syscall_num": [
            bytes([0x6a, 0x46, 0x58]),  # push 0x46; pop eax (70 is setreuid in 32-bit)
            bytes([0xb0, 0x46]),  # mov al, 0x46
            bytes([0x31, 0xc0, 0xb0, 0x46]),  # xor eax, eax; mov al, 0x46
            bytes([0xb8, 0x46, 0x00, 0x00, 0x00]),  # mov eax, 0x46
            bytes([0x8d, 0x43, 0x46]),  # lea eax, [ebx+0x46]
        ],
        "setreuid_zero_args": [
            bytes([0x31, 0xdb, 0x31, 0xc9]),  # xor ebx, ebx; xor ecx, ecx (zero uid, zero gid)
            bytes([0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9]),  # xor eax, eax; xor ebx, ebx; xor ecx, ecx
            bytes([0x6a, 0x00, 0x5b, 0x6a, 0x00, 0x59]),  # push 0x0; pop ebx; push 0x0; pop ecx
            bytes([0xbb, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0x00]),  # mov ebx, 0; mov ecx, 0
            bytes([0x53, 0x51]),  # push ebx; push ecx (when ebx and ecx are already 0)
        ],
        # specific patterns for 32-bit setreuid(0,0) shellcodes
        "specific": [
            # setreuid(0,0) pattern
            bytes([0x31, 0xdb, 0x31, 0xc9, 0x6a, 0x46, 0x58, 0xcd, 0x80]),
            # xor ebx, ebx; xor ecx, ecx; push 0x46; pop eax; int 0x80

            # alternative setreuid(0,0) pattern
            bytes([0x31, 0xc0, 0x31, 0xdb, 0x31, 0xc9, 0xb0, 0x46, 0xcd, 0x80]),
            # xor eax, eax; xor ebx, ebx; xor ecx, ecx; mov al, 0x46; int 0x80

            # LEA variant
            bytes([0x31, 0xdb, 0x31, 0xc9, 0x8d, 0x43, 0x46, 0xcd, 0x80]),
            # xor ebx, ebx; xor ecx, ecx; lea eax, [ebx+0x46]; int 0x80

            # push/pop variant
            bytes([0x6a, 0x00, 0x5b, 0x6a, 0x00, 0x59, 0x6a, 0x46, 0x58, 0xcd, 0x80]),
            # push 0x0; pop ebx; push 0x0; pop ecx; push 0x46; pop eax; int 0x80
        ]
    },
    "64bit": {
        "syscall": [
            bytes([0x0f, 0x05])  # syscall instruction
        ],
        "setreuid_syscall_num": [
            bytes([0xb0, 0x77]),  # mov al, 0x77 (119 is setreuid in 64-bit)
            bytes([0x6a, 0x77, 0x58]),  # push 0x77; pop rax
            bytes([0x48, 0xc7, 0xc0, 0x77, 0x00, 0x00, 0x00]),  # mov rax, 0x77
        ],
        "setreuid_zero_args": [
            bytes([0x48, 0x31, 0xff, 0x48, 0x31, 0xf6]),  # xor rdi, rdi; xor rsi, rsi
            bytes([0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00]),
            # mov rdi, 0; mov rsi, 0
            bytes([0x6a, 0x00, 0x5f, 0x6a, 0x00, 0x5e]),  # push 0; pop rdi; push 0; pop rsi
        ],
        # specific patterns for 64-bit setreuid(0,0) shellcodes
        "specific": [
            # setreuid(0,0) pattern
            bytes([0x48, 0x31, 0xff, 0x48, 0x31, 0xf6, 0xb0, 0x77, 0x0f, 0x05]),
            # xor rdi, rdi; xor rsi, rsi; mov al, 0x77; syscall

            # alternative setreuid(0,0) pattern
            bytes([0x48, 0x31, 0xff, 0x48, 0x31, 0xf6, 0x48, 0xc7, 0xc0, 0x77, 0x00, 0x00, 0x00, 0x0f, 0x05]),
            # xor rdi, rdi; xor rsi, rsi; mov rax, 0x77; syscall

            # push/pop variant
            bytes([0x6a, 0x00, 0x5f, 0x6a, 0x00, 0x5e, 0x6a, 0x77, 0x58, 0x0f, 0x05]),
            # push 0; pop rdi; push 0; pop rsi; push 0x77; pop rax; syscall
        ]
    }
}

# combinations for setreuid(0,0) shellcode
pattern_combinations = {
    "32bit": [
        ["syscall", "setreuid_syscall_num", "setreuid_zero_args"],
        # Combination of syscall, setreuid syscall number, and zero arguments
        ["setreuid_syscall_num", "setreuid_zero_args", "syscall"],  # Different order
        ["specific"]  # Known specific patterns
    ],
    "64bit": [
        ["syscall", "setreuid_syscall_num", "setreuid_zero_args"],
        # Combination of syscall, setreuid syscall number, and zero arguments
        ["setreuid_syscall_num", "setreuid_zero_args", "syscall"],  # Different order
        ["specific"]  # Known specific patterns
    ]
}

# additional sequences
related_patterns = {
    "32bit": [
        # setgid(0) sequence
        bytes([0x6a, 0x2e, 0x58, 0x31, 0xdb, 0xcd, 0x80]),  # push 0x2e; pop eax; xor ebx, ebx; int 0x80

        # execve sequence
        bytes([0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e]),  # Common execve setup
        bytes([0xb0, 0x0b, 0xcd, 0x80]),  # mov al, 0x0b; int 0x80 (execve)
    ],
    "64bit": [
        # setgid(0) sequence
        bytes([0xb0, 0x6a, 0x48, 0x31, 0xff, 0x0f, 0x05]),  # mov al, 0x6a; xor rdi, rdi; syscall

        # execve sequence
        bytes([0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # Common execve setup
        bytes([0xb0, 0x3b, 0x0f, 0x05]),  # mov al, 0x3b; syscall (execve)
    ]
}