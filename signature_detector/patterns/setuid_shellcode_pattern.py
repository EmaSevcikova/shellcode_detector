# Patterns for setuid(0) shellcode detection
# Behavior patterns organized by architecture and category
behavior_patterns = {
    "32bit": {
        "syscall": [
            bytes([0xcd, 0x80])  # int 0x80 (32-bit syscall)
        ],
        "setuid_syscall_num": [
            bytes([0x6a, 0x17, 0x58]),  # push 0x17; pop eax
            bytes([0xb0, 0x17]),  # mov al, 0x17
            bytes([0x31, 0xc0, 0xb0, 0x17]),  # xor eax, eax; mov al, 0x17
            bytes([0xb8, 0x17, 0x00, 0x00, 0x00]),  # mov eax, 0x17
            bytes([0x8d, 0x43, 0x17]),  # lea eax, [ebx+0x17]
        ],
        "setuid_zero_arg": [
            bytes([0x31, 0xdb]),  # xor ebx, ebx
            bytes([0x31, 0xc0, 0x31, 0xdb]),  # xor eax, eax; xor ebx, ebx
            bytes([0x6a, 0x00, 0x5b]),  # push 0x0; pop ebx
            bytes([0xbb, 0x00, 0x00, 0x00, 0x00]),  # mov ebx, 0
        ],
        # Add specific patterns for 32-bit setuid(0) shellcodes
        "specific": [
            # Pattern 1: Common setuid(0) pattern
            bytes([0x31, 0xdb, 0x6a, 0x17, 0x58, 0xcd, 0x80]),  # xor ebx, ebx; push 0x17; pop eax; int 0x80

            # Pattern 2: Alternative setuid(0) pattern
            bytes([0x31, 0xc0, 0x31, 0xdb, 0xb0, 0x17, 0xcd, 0x80]),
            # xor eax, eax; xor ebx, ebx; mov al, 0x17; int 0x80

            # Pattern 3: LEA variant
            bytes([0x31, 0xdb, 0x8d, 0x43, 0x17, 0x99, 0xcd, 0x80]),  # xor ebx, ebx; lea eax, [ebx+0x17]; cdq; int 0x80

            # Pattern 4: cdq variant
            bytes([0x31, 0xdb, 0x6a, 0x17, 0x58, 0x99, 0xcd, 0x80]),  # xor ebx, ebx; push 0x17; pop eax; cdq; int 0x80
        ]
    },
    "64bit": {
        "syscall": [
            bytes([0x0f, 0x05])  # syscall instruction
        ],
        "setuid_syscall_num": [
            bytes([0xb0, 0x69]),  # mov al, 0x69 (105 is setuid in 64-bit)
            bytes([0x6a, 0x69, 0x58]),  # push 0x69; pop rax
            bytes([0x48, 0xc7, 0xc0, 0x69, 0x00, 0x00, 0x00]),  # mov rax, 0x69
        ],
        "setuid_zero_arg": [
            bytes([0x48, 0x31, 0xff]),  # xor rdi, rdi
            bytes([0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00]),  # mov rdi, 0
            bytes([0x6a, 0x00, 0x5f]),  # push 0; pop rdi
        ],
        # Add specific patterns for 64-bit setuid(0) shellcodes
        "specific": [
            # Pattern 1: Common 64-bit setuid(0) pattern
            bytes([0x48, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05]),  # xor rdi, rdi; mov al, 0x69; syscall

            # Pattern 2: Alternative 64-bit setuid(0) pattern
            bytes([0x48, 0x31, 0xff, 0x48, 0xc7, 0xc0, 0x69, 0x00, 0x00, 0x00, 0x0f, 0x05]),
            # xor rdi, rdi; mov rax, 0x69; syscall
        ]
    }
}

# Define combinations that strongly indicate setuid(0) shellcode
pattern_combinations = {
    "32bit": [
        ["syscall", "setuid_syscall_num", "setuid_zero_arg"],
        # Combination of syscall, setuid syscall number, and zero argument
        ["setuid_syscall_num", "setuid_zero_arg", "syscall"],  # Different order
        ["specific"]  # Known specific patterns
    ],
    "64bit": [
        ["syscall", "setuid_syscall_num", "setuid_zero_arg"],
        # Combination of syscall, setuid syscall number, and zero argument
        ["setuid_syscall_num", "setuid_zero_arg", "syscall"],  # Different order
        ["specific"]  # Known specific patterns
    ]
}

# Confidence values for each component category
component_confidence = {
    "syscall": 0.2,
    "setuid_syscall_num": 0.4,
    "setuid_zero_arg": 0.4,
    "specific": 0.9  # High confidence for specific known patterns
}

# Additional sequences that often appear after setuid(0) to watch for
follow_up_patterns = {
    "32bit": [
        # setgid(0) sequence - often follows setuid(0)
        bytes([0x6a, 0x2e, 0x58, 0x31, 0xdb, 0xcd, 0x80]),  # push 0x2e; pop eax; xor ebx, ebx; int 0x80
        bytes([0x6a, 0x2e, 0x58, 0x53, 0xcd, 0x80]),  # push 0x2e; pop eax; push ebx; int 0x80

        # execve sequence - often follows privilege escalation
        bytes([0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e]),  # Common execve setup
    ],
    "64bit": [
        # execve sequence - often follows privilege escalation
        bytes([0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # Common execve setup
        bytes([0xb0, 0x3b, 0x0f, 0x05]),  # mov al, 0x3b; syscall (execve)
    ]
}