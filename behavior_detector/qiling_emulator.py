from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_OS, QL_ARCH
import capstone
import os


def instruction_hook(ql, address, size, arch):
    try:
        code = ql.mem.read(address, size)

        if arch == '32':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif arch == '64':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            raise ValueError("Invalid architecture. Must be '32' or '64'")

        for insn in md.disasm(code, address):
            print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
    except Exception as e:
        print(f"Error in instruction hook: {str(e)}")


def emulate_shellcode(shellcode_hex, arch='32'):
    try:
        # current directory
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # validate shellcode hex
        try:
            shellcode = bytes.fromhex(shellcode_hex)
        except ValueError:
            print("Error: Invalid shellcode hex string")
            return None, None

        if arch == '32':
            rootfs = os.path.join(script_dir, 'rootfs/x86_linux_glibc2.39')
            archtype = QL_ARCH.X86
        elif arch == '64':
            rootfs = os.path.join(script_dir, 'rootfs/x8664_linux_glibc2.39')
            archtype = QL_ARCH.X8664
        else:
            print("Error: Invalid architecture. Must be '32' or '64'")
            return None, None

        # debug information
        print(f"Script directory: {script_dir}")
        print(f"Looking for rootfs at: {rootfs}")
        print(f"Directory exists: {os.path.exists(rootfs)}")

        # check if rootfs exists
        if not os.path.exists(rootfs):
            print(f"Error: Rootfs directory not found at {rootfs}")
            return None, None

        try:
            ql = Qiling(
                code=shellcode,
                rootfs=rootfs,
                archtype=archtype,
                ostype=QL_OS.LINUX,
                verbose=QL_VERBOSE.DEBUG
            )

            ql.hook_code(lambda ql, address, size: instruction_hook(ql, address, size, arch))
            ql.run()

            syscalls = [key.replace("ql_syscall_", "") for key in ql.os.stats.syscalls.keys()]
            strings = list(ql.os.stats.strings.keys())

            return syscalls, strings

        except Exception as e:
            print(f"Error during emulation: {str(e)}")
            return None, None
    except Exception as e:
        print(f"Error: {str(e)}")
        return None, None
