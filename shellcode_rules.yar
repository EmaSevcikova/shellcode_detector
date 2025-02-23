rule Detect_Execve_Shellcode
{
    meta:
        author = "hackers name"
        description = "Detects execve shellcode for executing /bin/sh"
        reference = "gpt"

    strings:
        $execve_binsh = { 31 C0 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 B0 0B CD 80 }

    condition:
        $execve_binsh
}
rule Detect_Syscall_Shellcode_x86
{
    meta:
        author = "hackers name"
        description = "Detects x86 syscall-based shellcode patterns"
        reference = "gpt"

    strings:
        $syscall_pattern = { B8 ?? ?? ?? ?? CD 80 }

    condition:
        $syscall_pattern
}
rule Detect_Syscall_Shellcode_x64
{
    meta:
        author = "hackers name"
        description = "Detects x64 syscall-based shellcode patterns"
        reference = "gpt"

    strings:
        $syscall_pattern_64 = { 48 31 C0 48 89 C7 48 89 C6 48 89 D2 0F 05 }

    condition:
        $syscall_pattern_64
}
rule Detect_Stack_Pivot_x86
{
    meta:
        author = "hackers name"
        description = "Detects x86 stack pivoting in shellcode"
        reference = "gpt"

    strings:
        $stack_pivot_x86 = { 89 E5 83 EC ?? }

    condition:
        $stack_pivot_x86
}
rule Detect_Stack_Pivot_x64
{
    meta:
        author = "hackers name"
        description = "Detects x64 stack pivoting in shellcode"
        reference = "gpt"

    strings:
        $stack_pivot_x64 = { 48 89 E5 48 83 EC ?? }

    condition:
        $stack_pivot_x64
}
rule Detect_XOR_Decoder
{
    meta:
        author = "hackers name"
        description = "Detects XOR decoder shellcode (used in obfuscated shellcode)"
        reference = "gpt"

    strings:
        $xor_decoder = { 31 C9 F7 E1 }

    condition:
        $xor_decoder
}
rule shellcode
{
    meta:
        author = "nex"
        description = "Matched shellcode byte patterns"
        modified = "Glenn Edwards (@hiddenillusion)"
    strings:
        $s0 = { 64 8b 64 }
        $s1 = { 64 a1 30 }
        $s2 = { 64 8b 15 30 }
        $s3 = { 64 8b 35 30 }
        $s4 = { 55 8b ec 83 c4 }
        $s5 = { 55 8b ec 81 ec }
        $s6 = { 55 8b ec e8 }
        $s7 = { 55 8b ec e9 }
    condition:
        for any of ($s*) : ($ at entrypoint)
}