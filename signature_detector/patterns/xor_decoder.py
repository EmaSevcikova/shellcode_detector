name = "encoded shellcode"
# Improved detection patterns for XOR decoders
# Behavior patterns organized by architecture and category with expanded coverage

behavior_patterns = {
    "32bit": {
        "decoder_setup": [
            # Register initialization and counter setup
            bytes([0x31, 0xc0]),  # xor eax, eax
            bytes([0x31, 0xc9]),  # xor ecx, ecx
            bytes([0x31, 0xd2]),  # xor edx, edx
            bytes([0x31, 0xdb]),  # xor ebx, ebx
            bytes([0x31, 0xff]),  # xor edi, edi
            bytes([0x33, 0xc0]),  # xor eax, eax (alternative encoding)
            bytes([0x33, 0xc9]),  # xor ecx, ecx (alternative encoding)
            bytes([0x29, 0xc0]),  # sub eax, eax (zero register)
            bytes([0x29, 0xc9]),  # sub ecx, ecx (zero register)
            bytes([0xb1]),  # mov cl, immediate (setting counter)
            bytes([0xb9]),  # mov ecx, immediate (setting counter)
            bytes([0xb8]),  # mov eax, immediate (setting key/counter)
            bytes([0xbb]),  # mov ebx, immediate (setting address)
            bytes([0xbe]),  # mov esi, immediate (setting address)
            bytes([0xbf]),  # mov edi, immediate (setting address)
            bytes([0x5e]),  # pop esi (get address after call)
            bytes([0x5f]),  # pop edi (get address after call)
            bytes([0x59]),  # pop ecx (get address after call)
            bytes([0x58]),  # pop eax (get address after call)
            bytes([0x5b]),  # pop ebx (get address after call)
        ],
        "decoder_loop": [
            # XOR operations
            bytes([0x30]),  # xor byte ptr [], reg (byte xor)
            bytes([0x31]),  # xor dword ptr [], reg (word xor)
            bytes([0x80, 0x30]),  # xor byte ptr [eax], immediate
            bytes([0x80, 0x31]),  # xor byte ptr [ecx], immediate
            bytes([0x80, 0x32]),  # xor byte ptr [edx], immediate
            bytes([0x80, 0x33]),  # xor byte ptr [ebx], immediate
            bytes([0x80, 0x34]),  # xor byte ptr [esp], immediate
            bytes([0x80, 0x35]),  # xor byte ptr [ebp], immediate
            bytes([0x80, 0x36]),  # xor byte ptr [esi], immediate
            bytes([0x80, 0x37]),  # xor byte ptr [edi], immediate
            bytes([0x80, 0x38]),  # cmp byte ptr [eax], immediate (often follows XOR)
            bytes([0x35]),  # xor eax, immediate (xor to eax)
            bytes([0x34]),  # xor al, immediate (xor to al)

            # Memory pointer manipulation
            bytes([0x40]),  # inc eax (pointer manipulation)
            bytes([0x41]),  # inc ecx (counter/pointer manipulation)
            bytes([0x42]),  # inc edx (pointer manipulation)
            bytes([0x43]),  # inc ebx (pointer manipulation)
            bytes([0x46]),  # inc esi (pointer manipulation)
            bytes([0x47]),  # inc edi (pointer manipulation)
            bytes([0x48]),  # dec eax (counter manipulation)
            bytes([0x49]),  # dec ecx (counter manipulation)
            bytes([0x4a]),  # dec edx (counter manipulation)
            bytes([0x4b]),  # dec ebx (counter manipulation)
            bytes([0x4e]),  # dec esi (counter manipulation)
            bytes([0x4f]),  # dec edi (counter manipulation)
            bytes([0xff, 0xc0]),  # inc eax (alternative encoding)
            bytes([0xff, 0xc1]),  # inc ecx (alternative encoding)
            bytes([0xff, 0xc6]),  # inc esi (alternative encoding)
            bytes([0xff, 0xc7]),  # inc edi (alternative encoding)
            bytes([0xff, 0xc8]),  # dec eax (alternative encoding)
            bytes([0xff, 0xc9]),  # dec ecx (alternative encoding)
            bytes([0xff, 0xce]),  # dec esi (alternative encoding)
            bytes([0xff, 0xcf]),  # dec edi (alternative encoding)

            # Loop control
            bytes([0xe2]),  # loop instruction (loop relative)
            bytes([0xe0]),  # loopne/loopnz instruction
            bytes([0xe1]),  # loope/loopz instruction
            bytes([0x75]),  # jnz (jump if not zero - common in loops)
            bytes([0x74]),  # jz (jump if zero - end of loop)
            bytes([0x7c]),  # jl (jump if less - loop control)
            bytes([0x7d]),  # jge (jump if greater or equal - loop control)
            bytes([0x7e]),  # jle (jump if less or equal - loop control)
            bytes([0x7f]),  # jg (jump if greater - loop control)
            bytes([0xeb]),  # jmp short (often used in loops)
            bytes([0x39]),  # cmp (compare before jump)
            bytes([0x3b]),  # cmp (compare before jump)
            bytes([0x83, 0xf9]),  # cmp ecx, immediate (loop control)
            bytes([0x83, 0xf8]),  # cmp eax, immediate (loop control)
            bytes([0x83, 0xfe]),  # cmp esi, immediate (loop control)
            bytes([0x83, 0xff]),  # cmp edi, immediate (loop control)

            # Memory access
            bytes([0x8a]),  # mov al, memory (byte access)
            bytes([0x88]),  # mov memory, al (byte store)
            bytes([0x8b]),  # mov eax, memory (word access)
            bytes([0x89]),  # mov memory, eax (word store)
            bytes([0xaa]),  # stosb (store byte to memory)
            bytes([0xac]),  # lodsb (load byte from memory)
            bytes([0xab]),  # stosd (store dword to memory)
            bytes([0xad]),  # lodsd (load dword from memory)
        ],
        "decoder_call": [
            # JMP-CALL-POP technique
            bytes([0xeb]),  # jmp short (jump to call)
            bytes([0xe9]),  # jmp near (jump to call or decoded shellcode)
            bytes([0xe8]),  # call (to push EIP for position independent code)
            bytes([0xff, 0xd0]),  # call eax (call to decoder or decoded shellcode)
            bytes([0xff, 0xd1]),  # call ecx (call to decoder or decoded shellcode)
            bytes([0xff, 0xd2]),  # call edx (call to decoder or decoded shellcode)
            bytes([0xff, 0xd3]),  # call ebx (call to decoder or decoded shellcode)
            bytes([0xff, 0xd6]),  # call esi (call to decoder or decoded shellcode)
            bytes([0xff, 0xd7]),  # call edi (call to decoder or decoded shellcode)
            bytes([0xff, 0xe0]),  # jmp eax (jump to decoded payload)
            bytes([0xff, 0xe1]),  # jmp ecx (jump to decoded payload)
            bytes([0xff, 0xe2]),  # jmp edx (jump to decoded payload)
            bytes([0xff, 0xe3]),  # jmp ebx (jump to decoded payload)
            bytes([0xff, 0xe4]),  # jmp esp (jump to decoded payload)
            bytes([0xff, 0xe5]),  # jmp ebp (jump to decoded payload)
            bytes([0xff, 0xe6]),  # jmp esi (jump to decoded payload)
            bytes([0xff, 0xe7]),  # jmp edi (jump to decoded payload)
            bytes([0xc3]),  # ret (return to caller after decoding)
        ],
        "specific": [
            # Common complete 32-bit XOR decoder patterns
            bytes([0xeb, 0x0d, 0x5e, 0x31, 0xc9]),  # jmp short, pop esi, xor ecx, ecx
            bytes([0xeb, 0x0e, 0x5e, 0x31, 0xc9, 0xb1]),  # jmp short, pop esi, xor ecx, ecx, mov cl
            bytes([0xe8, 0xff, 0xff, 0xff, 0xff, 0xc3]),  # call $+5, ret (get EIP technique)
            bytes([0xe8, 0x00, 0x00, 0x00, 0x00, 0x5e]),  # call $+5, pop esi (get EIP technique)
            bytes([0x31, 0xc9, 0xb1]),  # xor ecx, ecx, mov cl, immediate (setup)
            bytes([0x80, 0x36]),  # xor byte ptr [esi], immediate
            bytes([0x80, 0x34, 0x0e]),  # xor byte ptr [esi+ecx], immediate
            bytes([0x46, 0xe2, 0xfa]),  # inc esi, loop (back 6 bytes)
            bytes([0x46, 0xe2, 0xf9]),  # inc esi, loop (back 7 bytes)
            bytes([0x46, 0xe2, 0xf8]),  # inc esi, loop (back 8 bytes)
            bytes([0x46, 0xe2, 0xfc]),  # inc esi, loop (back 4 bytes)
            bytes([0x31, 0xdb, 0x31, 0xc9]),  # xor ebx, ebx, xor ecx, ecx (init)
        ]
    },
    "64bit": {
        "decoder_setup": [
            # Register initialization and counter setup
            bytes([0x48, 0x31, 0xc0]),  # xor rax, rax
            bytes([0x48, 0x31, 0xc9]),  # xor rcx, rcx
            bytes([0x48, 0x31, 0xd2]),  # xor rdx, rdx
            bytes([0x48, 0x31, 0xdb]),  # xor rbx, rbx
            bytes([0x48, 0x31, 0xff]),  # xor rdi, rdi
            bytes([0x48, 0x29, 0xc0]),  # sub rax, rax (zero register)
            bytes([0x48, 0x29, 0xc9]),  # sub rcx, rcx (zero register)
            bytes([0x31, 0xc0]),  # xor eax, eax (zero register - sets upper 32 bits to zero)
            bytes([0x31, 0xc9]),  # xor ecx, ecx (zero register - sets upper 32 bits to zero)
            bytes([0xb1]),  # mov cl, immediate (setting counter)
            bytes([0xb9]),  # mov ecx, immediate (setting counter)
            bytes([0x48, 0xc7, 0xc0]),  # mov rax, immediate (setting key/counter)
            bytes([0x48, 0xc7, 0xc1]),  # mov rcx, immediate (setting counter)
            bytes([0x48, 0xc7, 0xc3]),  # mov rbx, immediate (setting address)
            bytes([0x48, 0xc7, 0xc6]),  # mov rsi, immediate (setting address)
            bytes([0x48, 0xc7, 0xc7]),  # mov rdi, immediate (setting address)
            bytes([0x5e]),  # pop rsi (get address after call)
            bytes([0x5f]),  # pop rdi (get address after call)
            bytes([0x59]),  # pop rcx (get address after call)
            bytes([0x58]),  # pop rax (get address after call)
            bytes([0x5b]),  # pop rbx (get address after call)
        ],
        "decoder_loop": [
            # XOR operations
            bytes([0x48, 0x31]),  # xor register, register (64-bit)
            bytes([0x48, 0x83, 0xf0]),  # xor rax, immediate
            bytes([0x48, 0x80, 0x30]),  # xor byte ptr [rax], immediate
            bytes([0x48, 0x80, 0x31]),  # xor byte ptr [rcx], immediate
            bytes([0x48, 0x80, 0x32]),  # xor byte ptr [rdx], immediate
            bytes([0x48, 0x80, 0x33]),  # xor byte ptr [rbx], immediate
            bytes([0x48, 0x80, 0x34]),  # xor byte ptr [rsp], immediate
            bytes([0x48, 0x80, 0x35]),  # xor byte ptr [rbp], immediate
            bytes([0x48, 0x80, 0x36]),  # xor byte ptr [rsi], immediate
            bytes([0x48, 0x80, 0x37]),  # xor byte ptr [rdi], immediate
            bytes([0x30]),  # xor byte ptr [], reg
            bytes([0x31]),  # xor dword ptr [], reg
            bytes([0x80, 0x30]),  # xor byte ptr [rax], immediate
            bytes([0x80, 0x36]),  # xor byte ptr [rsi], immediate
            bytes([0x80, 0x37]),  # xor byte ptr [rdi], immediate
            bytes([0x34]),  # xor al, immediate

            # Memory pointer manipulation
            bytes([0x48, 0xff, 0xc0]),  # inc rax
            bytes([0x48, 0xff, 0xc1]),  # inc rcx
            bytes([0x48, 0xff, 0xc2]),  # inc rdx
            bytes([0x48, 0xff, 0xc3]),  # inc rbx
            bytes([0x48, 0xff, 0xc6]),  # inc rsi
            bytes([0x48, 0xff, 0xc7]),  # inc rdi
            bytes([0x48, 0xff, 0xc8]),  # dec rax
            bytes([0x48, 0xff, 0xc9]),  # dec rcx
            bytes([0x48, 0xff, 0xca]),  # dec rdx
            bytes([0x48, 0xff, 0xcb]),  # dec rbx
            bytes([0x48, 0xff, 0xce]),  # dec rsi
            bytes([0x48, 0xff, 0xcf]),  # dec rdi
            bytes([0x40, 0x80]),  # REX prefix with operation (can be inc/dec)
            bytes([0x40, 0xff]),  # REX prefix with inc/dec
            bytes([0x48, 0x83, 0xc0, 0x01]),  # add rax, 1 (increment)
            bytes([0x48, 0x83, 0xc1, 0x01]),  # add rcx, 1 (increment)
            bytes([0x48, 0x83, 0xc6, 0x01]),  # add rsi, 1 (increment)
            bytes([0x48, 0x83, 0xc7, 0x01]),  # add rdi, 1 (increment)

            # Loop control
            bytes([0xe2]),  # loop instruction (loop relative)
            bytes([0xe0]),  # loopne/loopnz instruction
            bytes([0xe1]),  # loope/loopz instruction
            bytes([0x75]),  # jnz (jump if not zero - common in loops)
            bytes([0x74]),  # jz (jump if zero - end of loop)
            bytes([0x7c]),  # jl (jump if less - loop control)
            bytes([0x7d]),  # jge (jump if greater or equal - loop control)
            bytes([0x7e]),  # jle (jump if less or equal - loop control)
            bytes([0x7f]),  # jg (jump if greater - loop control)
            bytes([0xeb]),  # jmp short (often used in loops)
            bytes([0x48, 0x39]),  # cmp (compare before jump)
            bytes([0x48, 0x3b]),  # cmp (compare before jump)
            bytes([0x48, 0x83, 0xf9]),  # cmp rcx, immediate (loop control)
            bytes([0x48, 0x83, 0xf8]),  # cmp rax, immediate (loop control)
            bytes([0x48, 0x83, 0xfe]),  # cmp rsi, immediate (loop control)
            bytes([0x48, 0x83, 0xff]),  # cmp rdi, immediate (loop control)

            # Memory access
            bytes([0x48, 0x8a]),  # mov al, memory (64-bit addr)
            bytes([0x48, 0x88]),  # mov memory, al (64-bit addr)
            bytes([0x48, 0x8b]),  # mov rax, memory (64-bit addr)
            bytes([0x48, 0x89]),  # mov memory, rax (64-bit addr)
            bytes([0x48, 0xaa]),  # stosb (store byte to memory)
            bytes([0x48, 0xac]),  # lodsb (load byte from memory)
            bytes([0x48, 0xab]),  # stosq (store quad to memory)
            bytes([0x48, 0xad]),  # lodsq (load quad from memory)
        ],
        "decoder_call": [
            # JMP-CALL-POP technique
            bytes([0xeb]),  # jmp short (jump to call)
            bytes([0xe9]),  # jmp near (jump to call or decoded shellcode)
            bytes([0xe8]),  # call (to push RIP for position independent code)
            bytes([0xff, 0xd0]),  # call rax
            bytes([0xff, 0xd1]),  # call rcx
            bytes([0xff, 0xd2]),  # call rdx
            bytes([0xff, 0xd3]),  # call rbx
            bytes([0xff, 0xd6]),  # call rsi
            bytes([0xff, 0xd7]),  # call rdi
            bytes([0xff, 0xe0]),  # jmp rax
            bytes([0xff, 0xe1]),  # jmp rcx
            bytes([0xff, 0xe2]),  # jmp rdx
            bytes([0xff, 0xe3]),  # jmp rbx
            bytes([0xff, 0xe4]),  # jmp rsp
            bytes([0xff, 0xe5]),  # jmp rbp
            bytes([0xff, 0xe6]),  # jmp rsi
            bytes([0xff, 0xe7]),  # jmp rdi
            bytes([0xc3]),  # ret (return to caller after decoding)
        ],
        "specific": [
            # Common complete 64-bit XOR decoder patterns
            bytes([0xeb, 0x10, 0x5f, 0x48, 0x31, 0xc9]),  # jmp short, pop rdi, xor rcx, rcx
            bytes([0xeb, 0x10, 0x5e, 0x48, 0x31, 0xc9]),  # jmp short, pop rsi, xor rcx, rcx
            bytes([0xe8, 0xff, 0xff, 0xff, 0xff, 0xc3]),  # call $+5, ret (get RIP technique)
            bytes([0xe8, 0x00, 0x00, 0x00, 0x00, 0x5f]),  # call $+5, pop rdi (get RIP technique)
            bytes([0x48, 0x31, 0xc9, 0xb1]),  # xor rcx, rcx, mov cl, immediate
            bytes([0x48, 0x31, 0xc0, 0x48, 0x31, 0xff]),  # Clear registers before decoding
            bytes([0x48, 0x80, 0x34, 0x07]),  # xor byte ptr [rdi+rax], immediate
            bytes([0x48, 0x80, 0x36]),  # xor byte ptr [rsi], immediate
            bytes([0x48, 0x80, 0x37]),  # xor byte ptr [rdi], immediate
            bytes([0x48, 0xff, 0xc6, 0xe2, 0xf8]),  # inc rsi, loop (back 8 bytes)
            bytes([0x48, 0xff, 0xc6, 0xe2, 0xf9]),  # inc rsi, loop (back 7 bytes)
            bytes([0x48, 0xff, 0xc7, 0xe2, 0xf8]),  # inc rdi, loop (back 8 bytes)
            bytes([0x48, 0xff, 0xc7, 0xe2, 0xf9]),  # inc rdi, loop (back 7 bytes)
        ]
    }
}

# Define pattern combinations that indicate XOR decoder when found together
pattern_combinations = {
    "32bit": [
        # ["decoder_setup", "decoder_loop", "decoder_call"],  # Complete decoder with all components
        # ["decoder_setup", "decoder_loop"],  # Setup and loop without explicit call
        # ["decoder_call", "decoder_loop"],  # Call technique with loop but minimal setup
        # ["decoder_setup", "decoder_call"],  # Setup and call, loop might be minimal
        ["specific"]  # Known common complete patterns
    ],
    "64bit": [
        # ["decoder_setup", "decoder_loop", "decoder_call"],  # Complete decoder with all components
        # ["decoder_setup", "decoder_loop"],  # Setup and loop without explicit call
        # ["decoder_call", "decoder_loop"],  # Call technique with loop but minimal setup
        # ["decoder_setup", "decoder_call"],  # Setup and call, loop might be minimal
        ["specific"]  # Known common complete patterns
    ]
}