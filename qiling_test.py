# from qiling import Qiling
# from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP
# import os
#
#
# def print_memory_map(ql):
#     """Prints current memory mappings in the emulator."""
#     print("\n[ Memory Map ]")
#     # Print the full information from ql.mem.get_mapinfo()
#     for region in ql.mem.get_mapinfo():
#         print(f"Region: {region}")
#
#
# def load_memory_dump(ql, dump_path, mappings, entry_point, stack_pointer):
#     """Loads memory regions from a core dump and sets execution context."""
#
#     for base_addr, size, perms in mappings:
#         # Ensure memory isn't already mapped
#         for region in ql.mem.get_mapinfo():  # Inspect the full tuple
#             print(f"Existing region: {region}")
#             start, end, _ = region[:3]  # Assuming it contains at least 3 values: start, end, and permissions
#             if start <= base_addr < end:
#                 print(f"Memory region {hex(base_addr)} - {hex(base_addr + size)} already mapped.")
#                 break
#         else:
#             ql.mem.map(base_addr, size, perms)  # Map memory
#             print(f"Mapped: {hex(base_addr)} - {hex(base_addr + size)} (Size: {size} bytes)")
#
#     with open(dump_path, "rb") as f:
#         dump_data = f.read()
#         for base_addr, size, _ in mappings:
#             ql.mem.write(base_addr, dump_data[:size])  # Load memory content
#             dump_data = dump_data[size:]  # Trim used bytes
#
#     print_memory_map(ql)
#
#     # Set registers
#     ql.uc.reg_write(UC_X86_REG_EIP, entry_point)
#     ql.uc.reg_write(UC_X86_REG_ESP, stack_pointer)
#
#     print(f"Entry point set to: {hex(entry_point)}")
#     print(f"Stack pointer set to: {hex(stack_pointer)}")
#
#
# # Memory layout extracted from gdb
# mappings = [
#     (0x8048000, 0x5000, 7),  # Main executable (RWX)
#     (0xf70e2000, 0x250000, 5),  # libc.so.6 (R-X)
#     (0xf733c000, 0x40000, 5),  # ld-linux.so.2 (R-X)
# ]
#
# # Extracted from `gdb info registers`
# ENTRY_POINT = 0x08049196  # Change this to your actual main()
# STACK_POINTER = 0xffa566f0  # ESP from gdb
#
# # Initialize Qiling without an external binary
# ql = Qiling(["hello"], "qiling/rootfs/x86_linux")
#
# # Print initial memory mappings
# print_memory_map(ql)
#
# # Load core dump and start emulation
# load_memory_dump(ql, "core.29474", mappings, ENTRY_POINT, STACK_POINTER)
# ql.run()

from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_OS, QL_ARCH

# Hook function to monitor system calls
def syscall_hook(ql, syscall_id, params):
    print(f"[*] Syscall Intercepted: {syscall_id}")
    print(f"    Arguments: {params}")

def detect_bin_sh(ql, addr=None, size=None):
    mem_dump = ql.mem.read(0x30000, 0x1000)
    if b"/bin/sh" in mem_dump:
        print("[!] Shellcode trying to execute /bin/sh detected!")

# Initialize Qiling emulator
def main():

    ql = Qiling(["test_data/shellcodes/shellcode2"], rootfs="qiling/rootfs/x8664_linux_glibc2.39",archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX,verbose=QL_VERBOSE.DEBUG)

    # # Linux shellcode: execve("/bin/sh", NULL, NULL)
    # shellcode = bytes.fromhex(
    #     "4831c05048bb2f2f62696e2f73685348c1eb08534889e74831f64831d2b03b0f05"
    # )

    # Instantiate Qiling to emulate the shellcode.
    # Specify 'Linux' as the operating system and 'x8664' as the architecture.
    # ql = Qiling(code=shellcode, rootfs=r'qiling/rootfs/x8664_linux_glibc2.39',archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX,
    #             verbose=QL_VERBOSE.DEBUG)

    # Set the syscall hook
    # ql.hook_code(syscall_hook)
    # ql.hook_code(detect_bin_sh)
    # ql.mem.get_formatted_mapinfo()

    # Start emulation
    ql.run()

if __name__ == "__main__":
    main()



