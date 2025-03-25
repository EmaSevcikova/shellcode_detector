# Bind shell behavior patterns organized by architecture and category
behavior_patterns = {
    "32bit": {
        "syscall": [
            bytes([0xcd, 0x80])  # int 0x80 (32-bit syscall)
        ],
        "socket_creation": [
            bytes([0x66, 0xb8]),  # mov ax, socket syscall
            bytes([0xb0, 0x66]),  # mov al, socket syscall
            bytes([0x6a, 0x66]),  # push socket syscall number
        ],
        "socket_ops": [
            # Bind, listen, accept syscall signatures
            bytes([0xb3, 0x02]),  # mov bl, bind operation
            bytes([0xb3, 0x04]),  # mov bl, listen operation
            bytes([0xb3, 0x05]),  # mov bl, accept operation
        ],
        "port_manipulation": [
            bytes([0x66, 0x68]),  # push word port number
            bytes([0x66, 0x53]),  # push port in network byte order
        ],
        "dup2_syscall": [
            bytes([0xb0, 0x3f]),  # mov al, dup2 syscall
            bytes([0xfe, 0xc9]),  # dec cl (loop counter)
        ],
        "execve_shell": [
            # Shell string and execve syscall patterns
            bytes([0x68, 0x6e, 0x2f, 0x73, 0x68]),  # push "/n/sh"
            bytes([0x68, 0x2f, 0x2f, 0x62, 0x69, 0x6e]),  # push "//bin"
            bytes([0xb0, 0x0b]),  # mov al, execve syscall
        ],
        "shell_string": [
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # "/bin/sh"
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68]),  # "/bin//sh"
        ]
    },
    "64bit": {
        "syscall": [
            bytes([0x0f, 0x05])  # syscall instruction
        ],
        "socket_creation": [
            bytes([0x6a, 0x29]),  # push socket syscall number
            bytes([0xb0, 0x29]),  # mov al, socket syscall
            bytes([0x48, 0xc7, 0xc0, 0x29, 0x00, 0x00, 0x00]),  # mov rax, socket syscall
        ],
        "socket_ops": [
            # Bind, listen, accept syscall signatures
            bytes([0x6a, 0x31]),  # push bind syscall number
            bytes([0x6a, 0x32]),  # push listen syscall number
            bytes([0x6a, 0x2b]),  # push accept syscall number
            bytes([0xb0, 0x31]),  # mov al, bind syscall
            bytes([0xb0, 0x32]),  # mov al, listen syscall
            bytes([0xb0, 0x2b]),  # mov al, accept syscall
        ],
        "port_manipulation": [
            bytes([0x66, 0x68]),  # push word port number
            bytes([0x66, 0x53]),  # push port in network byte order
            bytes([0xc6, 0x04, 0x24, 0x02]),  # set socket family to AF_INET
        ],
        "dup2_syscall": [
            bytes([0x6a, 0x21]),  # push dup2 syscall number
            bytes([0xb0, 0x21]),  # mov al, dup2 syscall
            bytes([0x48, 0xff, 0xce]),  # dec rsi (decrement file descriptor)
        ],
        "execve_shell": [
            # Shell string and execve syscall patterns
            bytes([0x6a, 0x3b]),  # push execve syscall number
            bytes([0xb0, 0x3b]),  # mov al, execve syscall
            bytes([0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00]),  # mov rax, execve syscall
        ],
        "shell_string": [
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # "/bin/sh"
            bytes([0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68]),  # "/bin//sh"
            bytes([0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # mov rbx, "/bin/sh"
            bytes([0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68]),  # mov rdi, "/bin/sh"
        ],
        "stack_arg_setup": [
            bytes([0x48, 0x31, 0xd2]),  # xor rdx, rdx (clear envp)
            bytes([0x52]),  # push rdx (NULL terminator)
            bytes([0x48, 0x89, 0xe6]),  # mov rsi, rsp (set arg pointer)
            bytes([0x48, 0x89, 0xe7]),  # mov rdi, rsp (set path)
        ]
    }
}

pattern_combinations = {
    "32bit": [
        ["syscall", "socket_creation", "socket_ops", "port_manipulation", "dup2_syscall", "execve_shell"],
        ["socket_creation", "socket_ops", "port_manipulation", "dup2_syscall", "execve_shell", "shell_string"],
        ["socket_creation", "port_manipulation", "dup2_syscall", "execve_shell"]
    ],
    "64bit": [
        ["syscall", "socket_creation", "socket_ops", "port_manipulation", "dup2_syscall", "execve_shell", "stack_arg_setup"],
        ["socket_creation", "socket_ops", "port_manipulation", "dup2_syscall", "execve_shell", "shell_string"],
        ["syscall", "socket_creation", "socket_ops", "port_manipulation", "dup2_syscall", "execve_shell"]
    ]
}