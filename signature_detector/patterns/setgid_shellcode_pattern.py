# Patterns for setgid(0) shellcode detection
# Behavior patterns organized by architecture and category
behavior_patterns = {
    "32bit": {
        "syscall": [
            bytes([0xcd, 0x80])  # int 0x80 (32-bit syscall)
        ],
        "setgid_syscall_num": [
            bytes([0x6a, 0x2e, 0x58]),  # push 0x2e; pop eax
            bytes([0xb0, 0x2e]),  # mov al, 0x2e
            bytes([0x31, 0xc0, 0xb0, 0x2e]),  # xor eax, eax; mov al, 0x2e
            bytes([0xb8, 0x2e, 0x00, 0x00, 0x00]),  # mov eax, 0x2e
        ],
        "setgid_zero_arg": [
            bytes([0x31, 0xdb]),  # xor ebx, ebx
            bytes([0x31, 0xc0, 0x31, 0xdb]),  # xor eax, eax; xor ebx, ebx
            bytes([0x6a, 0x00, 0x5b]),  # push 0x0; pop ebx
            bytes([0xbb, 0x00, 0x00, 0x00, 0x00]),  # mov ebx, 0
            bytes([0x53]),  # push ebx (when ebx is already 0)
        ],
        # Add specific patterns for 32-bit setgid(0) shellcodes
        "specific": [
            # Pattern 1: Common setgid(0) pattern
            bytes([0x6a, 0x2e, 0x58, 0x53, 0xcd, 0x80]),  # push 0x2e; pop eax; push ebx; int 0x80

            # Pattern 2: Alternative setgid(0) pattern
            bytes([0x6a, 0x2e, 0x58, 0x31, 0xdb, 0xcd, 0x80]),  # push 0x2e; pop eax; xor ebx, ebx; int 0x80

            # Pattern 3: Direct mov variant
            bytes([0x31, 0xdb, 0xb0, 0x2e, 0xcd, 0x80]),  # xor ebx, ebx; mov al, 0x2e; int 0x80

            # Pattern 4: With previous xor
            bytes([0x31, 0xc0, 0xb0, 0x2e, 0x31, 0xdb, 0xcd, 0x80]),
            # xor eax, eax; mov al, 0x2e; xor ebx, ebx; int 0x80

            # Pattern 5: With previous xor and just direct mov
            bytes([0x31, 0xc0, 0xb0, 0x2e, 0xcd, 0x80]),  # xor eax, eax; mov al, 0x2e; int 0x80 (ebx already zero)
        ]
    },
    "64bit": {
        "syscall": [
            bytes([0x0f, 0x05])  # syscall instruction
        ],
        "setgid_syscall_num": [
            bytes([0xb0, 0x6a]),  # mov al, 0x6a (106 is setgid in 64-bit)
            bytes([0x6a, 0x6a, 0x58]),  # push 0x6a; pop rax
            bytes([0x48, 0xc7, 0xc0, 0x6a, 0x00, 0x00, 0x00]),  # mov rax, 0x6a
        ],
        "setgid_zero_arg": [
            bytes([0x48, 0x31, 0xff]),  # xor rdi, rdi
            bytes([0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00]),  # mov rdi, 0
            bytes([0x6a, 0x00, 0x5f]),  # push 0; pop rdi
        ],
        # Add inferred patterns for 64-bit setgid(0) shellcodes
        "specific": [
            # Pattern 1: Likely 64-bit setgid(0) pattern
            bytes([0x48, 0x31, 0xff, 0xb0, 0x6a, 0x0f, 0x05]),  # xor rdi, rdi; mov al, 0x6a; syscall

            # Pattern 2: Alternative 64-bit setgid(0) pattern
            bytes([0x48, 0x31, 0xff, 0x48, 0xc7, 0xc0, 0x6a, 0x00, 0x00, 0x00, 0x0f, 0x05]),
            # xor rdi, rdi; mov rax, 0x6a; syscall
        ]
    }
}

# Define combinations that strongly indicate setgid(0) shellcode
pattern_combinations = {
    "32bit": [
        ["syscall", "setgid_syscall_num", "setgid_zero_arg"],
        # Combination of syscall, setgid syscall number, and zero argument
        ["setgid_syscall_num", "setgid_zero_arg", "syscall"],  # Different order
        ["specific"]  # Known specific patterns
    ],
    "64bit": [
        ["syscall", "setgid_syscall_num", "setgid_zero_arg"],
        # Combination of syscall, setgid syscall number, and zero argument
        ["setgid_syscall_num", "setgid_zero_arg", "syscall"],  # Different order
        ["specific"]  # Known specific patterns
    ]
}

# Common patterns that often appear before or after setgid(0)
related_patterns = {
    "32bit": {
        "before": [
            # setuid(0) sequence - often precedes setgid(0)
            bytes([0x31, 0xdb, 0x6a, 0x17, 0x58, 0xcd, 0x80]),  # xor ebx, ebx; push 0x17; pop eax; int 0x80
            bytes([0x31, 0xc0, 0xb0, 0x17, 0x31, 0xdb, 0xcd, 0x80]),
            # xor eax, eax; mov al, 0x17; xor ebx, ebx; int 0x80
        ],
        "after": [
            # execve sequence - often follows privilege escalation
            bytes([0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e]),
            # Common execve setup
            bytes([0x31, 0xc0, 0xb0, 0x0b]),  # xor eax, eax; mov al, 0xb
            bytes([0x6a, 0x0b, 0x58]),  # push 0xb; pop eax
        ]
    },
    "64bit": {
        "before": [
            # setuid(0) sequence - often precedes setgid(0)
            bytes([0x48, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05]),  # xor rdi, rdi; mov al, 0x69; syscall
        ],
        "after": [
            # execve sequence - often follows privilege escalation
            bytes([0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # Common execve setup
            bytes([0xb0, 0x3b, 0x0f, 0x05]),  # mov al, 0x3b; syscall (execve)
        ]
    }
}

# Sequential patterns that might indicate privilege escalation chains
privilege_escalation_chains = {
    "32bit": [
        # setuid(0) followed by setgid(0)
        bytes([0x31, 0xdb, 0x6a, 0x17, 0x58, 0xcd, 0x80, 0x6a, 0x2e, 0x58, 0x53, 0xcd, 0x80]),
        bytes([0x31, 0xc0, 0xb0, 0x17, 0x31, 0xdb, 0xcd, 0x80, 0xb0, 0x2e, 0xcd, 0x80]),

        # setuid(0) + setgid(0) + execve
        bytes(
            [0x31, 0xdb, 0x6a, 0x17, 0x58, 0xcd, 0x80, 0x6a, 0x2e, 0x58, 0x53, 0xcd, 0x80, 0x31, 0xc0, 0x50, 0x68, 0x2f,
             0x2f, 0x73, 0x68]),
    ],
    "64bit": [
        # setuid(0) followed by setgid(0) (inferred)
        bytes([0x48, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05, 0xb0, 0x6a, 0x0f, 0x05]),
    ]
}