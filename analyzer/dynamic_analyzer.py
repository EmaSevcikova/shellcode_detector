from unicorn import *
from unicorn.x86_const import *
import struct


def emulate_code(code, base_addr=0x1000):

    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    # Allocate memory for execution
    mem_size = len(code) + 0x1000  # Extra space for safety
    uc.mem_map(base_addr, mem_size)

    # Write code into Unicorn memory
    uc.mem_write(base_addr, code)

    # Shellcode detection flag
    shellcode_found = False

    # Hook for tracing instructions
    def trace_instructions(uc, address, size, user_data):
        nonlocal shellcode_found
        opcode = uc.mem_read(address, size)

        # Detect suspicious behavior
        if opcode[0] in [0xCD]:  # INT 0x80 (Linux syscall)
            print(f"[!] Syscall detected at 0x{address:x}, possible shellcode!")
            shellcode_found = True
        elif opcode[0] in [0xE8, 0xE9]:  # CALL/JMP
            target_addr = struct.unpack("<I", opcode[1:5])[0]
            print(f"[!] JMP/CALL to 0x{target_addr:x}, suspicious behavior!")
            shellcode_found = True

        print(f"[*] Executing instruction at 0x{address:x}: {opcode.hex()}")

    # Hook for detecting syscalls
    def hook_syscall(uc, user_data):
        nonlocal shellcode_found
        eax = uc.reg_read(UC_X86_REG_EAX)  # Syscall number
        print(f"[!] Syscall executed: EAX={eax:x}")
        shellcode_found = True

    # Add hooks
    uc.hook_add(UC_HOOK_CODE, trace_instructions)
    uc.hook_add(UC_HOOK_INTR, hook_syscall)

    try:
        print("[*] Starting emulation...")
        uc.emu_start(base_addr, base_addr + len(code))
    except UcError as e:
        print(f"[!] Emulation error: {e}")

    if shellcode_found:
        print("[!] Possible shellcode detected!")
        return True
    else:
        print("[+] No suspicious activity detected.")
        return False
