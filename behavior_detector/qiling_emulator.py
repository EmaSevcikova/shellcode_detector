from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_OS, QL_ARCH
import capstone

def instruction_hook(ql, address, size):
    code = ql.mem.read(address, size)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for insn in md.disasm(code, address):
        print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

def emulate_shellcode(shellcode_hex):
    shellcode = bytes.fromhex(shellcode_hex)

    ql = Qiling(
        code=shellcode,
        rootfs=r'rootfs/x86_linux_glibc2.39',
        archtype=QL_ARCH.X86,
        ostype=QL_OS.LINUX,
        verbose=QL_VERBOSE.DEBUG
    )

    ql.hook_code(instruction_hook)
    ql.run()