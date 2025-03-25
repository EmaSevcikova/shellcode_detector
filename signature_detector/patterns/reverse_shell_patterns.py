# Reverse shell behavior patterns organized by architecture and category
behavior_patterns = {
    "32bit": {
        "socket": [
            # Common socket syscall signatures
            bytes([0x66, 0x58]),  # pop eax with socket syscall number
            bytes([0xb0, 0x66]),  # mov al, socket syscall number
            bytes([0x6a, 0x66]),  # push socket syscall number

            # Socket domain and type indicators
            bytes([0x6a, 0x02]),  # push AF_INET
            bytes([0x6a, 0x01]),  # push SOCK_STREAM
            bytes([0x31, 0xd2]),  # xor edx, edx (protocol)
        ],
        "connect": [
            # Connect syscall signatures
            bytes([0xb0, 0x66]),  # mov al, connect syscall number
            bytes([0x43]),  # inc ebx (increment socket fd)
            bytes([0x66, 0x68]),  # pushw port
            bytes([0x68]),  # push IP address

            # Connect stack preparation patterns
            bytes([0x89, 0xe1]),  # mov ecx, esp (setup socket struct)
            bytes([0x6a, 0x10]),  # push struct length
        ],
        "dup2": [
            # File descriptor duplication patterns
            bytes([0xb0, 0x3f]),  # mov al, dup2 syscall number
            bytes([0x49]),  # dec ecx
            bytes([0x79, 0xf9]),  # jns dup2 loop
        ],
        "execve": [
            # Execve shell execution patterns
            bytes([0xb0, 0x0b]),  # mov al, execve syscall number
            bytes([0x68, 0x2f, 0x2f, 0x73, 0x68]),  # push //sh
            bytes([0x68, 0x2f, 0x62, 0x69, 0x6e]),  # push /bin
            bytes([0x89, 0xe3]),  # mov ebx, esp (command path)
        ],
        "shell_string": [
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # /bin/sh
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68]),  # /bin//sh
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68]),  # /bin/bash
        ]
    },
    "64bit": {
        "socket": [
            # Socket syscall signatures
            bytes([0x6a, 0x29]),  # push socket syscall number
            bytes([0x58]),  # pop rax
            bytes([0x6a, 0x02]),  # push AF_INET
            bytes([0x5f]),  # pop rdi
            bytes([0x6a, 0x01]),  # push SOCK_STREAM
            bytes([0x5e]),  # pop rsi
            bytes([0xcd, 0x80]),  # int 0x80 or syscall
            bytes([0x48, 0x31, 0xd2]),  # xor rdx, rdx (protocol)
        ],
        "connect": [
            # Connect syscall signatures
            bytes([0x6a, 0x2a]),  # push connect syscall number
            bytes([0x58]),  # pop rax

            # IP and Port setup patterns
            bytes([0xc7, 0x44, 0x24]),  # mov dword [rsp+x], IP
            bytes([0x66, 0xc7, 0x44, 0x24]),  # mov word [rsp+x], PORT

            # Socket struct preparation
            bytes([0x48, 0x89, 0xe6]),  # mov rsi, rsp
            bytes([0x6a, 0x10]),  # push struct length
        ],
        "dup2": [
            # File descriptor duplication patterns
            bytes([0x6a, 0x03]),  # push 3 (fd count)
            bytes([0x5e]),  # pop rsi
            bytes([0x6a, 0x21]),  # push dup2 syscall number
            bytes([0x58]),  # pop rax
            bytes([0x48, 0xff, 0xce]),  # dec rsi
            bytes([0x0f, 0x05]),  # syscall
            bytes([0x75, 0xf6]),  # jne dup2 loop
        ],
        "execve": [
            # Execve shell execution patterns
            bytes([0x6a, 0x3b]),  # push execve syscall number
            bytes([0x58]),  # pop rax

            # Shell string loading patterns
            bytes([0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # mov rdi, "/bin/sh"
            bytes([0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00]),  # mov rax, 59
            bytes([0x0f, 0x05]),  # syscall
        ],
        "shell_string": [
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # /bin/sh
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68]),  # /bin//sh
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68]),  # /bin/bash
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x7a, 0x73, 0x68]),  # /bin/zsh
        ]
    }
}

pattern_combinations = {
    "32bit": [
        ["socket", "connect", "dup2", "execve"],
        ["socket", "connect", "dup2", "shell_string"],
        ["socket", "connect", "execve", "shell_string"]
    ],
    "64bit": [
        ["socket", "connect", "dup2", "execve"],
        ["socket", "connect", "dup2", "shell_string"],
        ["socket", "connect", "execve", "shell_string"]
    ]
}