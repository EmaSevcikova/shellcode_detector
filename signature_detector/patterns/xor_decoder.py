# detection patterns for XOR decoders
# Behavior patterns organized by architecture and category
behavior_patterns = {
    "32bit": {
        "loop_setup": [
            bytes([0x31, 0xc9]),  # xor ecx, ecx (counter initialization)
            bytes([0xb1]),        # mov cl, immediate (setting counter)
            bytes([0xb9]),        # mov ecx, immediate (setting counter)
            bytes([0x41]),        # inc ecx (counter manipulation)
            bytes([0x49]),        # dec ecx (counter manipulation)
            bytes([0xe2]),        # loop instruction
        ],
        "memory_access": [
            bytes([0x8a]),        # mov al, memory (byte access)
            bytes([0x88]),        # mov memory, al (byte store)
            bytes([0x8b]),        # mov eax, memory (word access)
            bytes([0x89]),        # mov memory, eax (word store)
            bytes([0xaa]),        # stosb (store byte to memory)
            bytes([0xac]),        # lodsb (load byte from memory)
        ],
        "xor_operation": [
            bytes([0x30]),        # xor byte ptr [], reg (byte xor)
            bytes([0x31]),        # xor dword ptr [], reg (word xor)
            bytes([0x80, 0x30]),  # xor byte ptr [], immediate (byte xor with immediate)
            bytes([0x80, 0x31]),  # xor byte ptr [ecx], immediate (byte xor with immediate)
            bytes([0x80, 0x33]),  # xor byte ptr [ebx], immediate (byte xor with immediate)
            bytes([0x80, 0x34]),  # xor byte ptr [esp], immediate (byte xor with immediate)
            bytes([0x35]),        # xor eax, immediate (xor to eax)
            bytes([0x34]),        # xor al, immediate (xor to al)
        ],
        "jmp_call": [
            bytes([0xeb]),        # jmp short (often used to jump to decoder)
            bytes([0xe8]),        # call (often used to get EIP)
            bytes([0x5e]),        # pop esi (get address after call)
            bytes([0x59]),        # pop ecx (get address after call)
            bytes([0xff, 0xe4]),  # jmp esp (jump to decoded payload)
        ],
        "specific": [
            # Common 32-bit XOR decoder patterns
            bytes([0xeb, 0x0e, 0x5e, 0x31, 0xc9, 0xb1]),  # jmp call pop setup with counter
            bytes([0xe8, 0xff, 0xff, 0xff, 0xff, 0xc3, 0x5e]),  # call pop technique
            bytes([0x31, 0xc9, 0xb1, 0x30, 0x80, 0x34, 0x0e]),  # xor ecx, ecx; mov cl, len; xor [esi+ecx], imm
            bytes([0x31, 0xdb, 0x31, 0xc9, 0xb1]),  # Clear registers and set counter
        ]
    },
    "64bit": {
        "loop_setup": [
            bytes([0x48, 0x31, 0xc9]),  # xor rcx, rcx (counter initialization)
            bytes([0x48, 0xc7, 0xc1]),  # mov rcx, immediate (setting counter)
            bytes([0xb1]),              # mov cl, immediate (setting counter)
            bytes([0x48, 0xff, 0xc1]),  # inc rcx (counter manipulation)
            bytes([0x48, 0xff, 0xc9]),  # dec rcx (counter manipulation)
            bytes([0xe2]),              # loop instruction
        ],
        "memory_access": [
            bytes([0x48, 0x8a]),        # mov al, memory (64-bit addr)
            bytes([0x48, 0x88]),        # mov memory, al (64-bit addr)
            bytes([0x48, 0x8b]),        # mov rax, memory (64-bit addr)
            bytes([0x48, 0x89]),        # mov memory, rax (64-bit addr)
            bytes([0x48, 0xaa]),        # stosb (store byte to memory)
            bytes([0x48, 0xac]),        # lodsb (load byte from memory)
        ],
        "xor_operation": [
            bytes([0x48, 0x31]),        # xor register, register (64-bit)
            bytes([0x48, 0x83, 0xf0]),  # xor rax, immediate
            bytes([0x48, 0x80, 0x30]),  # xor byte ptr [rax], immediate
            bytes([0x48, 0x80, 0x31]),  # xor byte ptr [rcx], immediate
            bytes([0x48, 0x80, 0x37]),  # xor byte ptr [rdi], immediate
            bytes([0x30]),              # xor byte ptr [], reg
            bytes([0x31]),              # xor dword ptr [], reg
            bytes([0x34]),              # xor al, immediate
        ],
        "jmp_call": [
            bytes([0xeb]),              # jmp short
            bytes([0xe8]),              # call
            bytes([0x5e]),              # pop rsi
            bytes([0x5f]),              # pop rdi
            bytes([0xff, 0xe0]),        # jmp rax
            bytes([0xff, 0xe7]),        # jmp rdi
        ],
        "specific": [
            # Common 64-bit XOR decoder patterns
            bytes([0xeb, 0x10, 0x5f, 0x48, 0x31, 0xc9, 0x80, 0x37]),  # jmp call pop with byte xor
            bytes([0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0xb0]),  # Clear registers before decoding
            bytes([0xe8, 0xff, 0xff, 0xff, 0xff, 0xc3, 0x5f, 0x48]),  # call pop in 64-bit
            bytes([0x48, 0x31, 0xc9, 0x48, 0xff, 0xc1, 0x80, 0x34, 0x0f]),  # xor-based loop decoder
        ]
    }
}

# Define pattern combinations that indicate XOR decoder when found together
pattern_combinations = {
    "32bit": [
        ["loop_setup", "xor_operation", "memory_access"],  # Loop with XOR and memory access
        ["jmp_call", "xor_operation", "memory_access"],    # Get-PC technique with XOR decoder
        ["loop_setup", "xor_operation"],                  # Simple loop with XOR operations
        ["jmp_call", "loop_setup", "xor_operation"]       # JMP/CALL with loop and XOR
    ],
    "64bit": [
        ["loop_setup", "xor_operation", "memory_access"],  # Loop with XOR and memory access
        ["jmp_call", "xor_operation", "memory_access"],    # Get-PC technique with XOR decoder
        ["loop_setup", "xor_operation"],                  # Simple loop with XOR operations
        ["jmp_call", "loop_setup", "xor_operation"]       # JMP/CALL with loop and XOR
    ]
}

# Confidence values for each component category
component_confidence = {
    "loop_setup": 0.25,
    "memory_access": 0.2,
    "xor_operation": 0.3,
    "jmp_call": 0.15,
    "specific": 0.9  # High confidence for specific known patterns
}