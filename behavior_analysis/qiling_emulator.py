from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_OS, QL_ARCH
import capstone
import os
import multiprocessing


def instruction_hook(ql, address, size, arch):
    """Disassembles and prints instructions at a given memory address during emulation."""
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


def _run_emulation(shellcode, rootfs, archtype, arch, result_queue):
    """Runs shellcode in the Qiling emulator, capturing system calls and strings used."""
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

        result_queue.put((syscalls, strings))
    except Exception as e:
        print(f"Error during emulation: {str(e)}")
        result_queue.put((None, None))


def emulate_shellcode(shellcode_hex, arch='32', timeout=5):
    """Emulates shellcode in a sandboxed Linux environment using Qiling and returns system calls and strings used."""
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

        # Use multiprocessing to run emulation with timeout
        result_queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=_run_emulation,
            args=(shellcode, rootfs, archtype, arch, result_queue)
        )

        process.start()

        # wait for result or timeout
        process.join(timeout)

        if process.is_alive():
            print(f"Shellcode execution timed out after {timeout} seconds")
            process.terminate()
            process.join()
            return ['timeout'], ['execution_timed_out']

        if not result_queue.empty():
            return result_queue.get()
        else:
            print("Emulation completed but no results were returned")
            return None, None

    except Exception as e:
        print(f"Error: {str(e)}")
        return None, None