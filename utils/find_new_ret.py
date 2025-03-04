import subprocess
import re


def find_address(binary, buf_size, buf_size_hex):
    """
    Runs GDB, executes the payload, and extracts $ebp - buf_size_hex.

    Returns the computed memory address in hex format.
    """

    gdb_commands = f"""
    set pagination off
    file {binary}
    break func
    run $(python3 -c 'print("A"*{buf_size})')
    print $ebp
    print $ebp - {buf_size_hex}
    quit
    """

    process = subprocess.Popen(
        ["gdb", "-q", binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = process.communicate(gdb_commands)

    # filter stdout
    relevant_output = []
    for line in stdout.splitlines():
        if "$1" in line or "$2" in line:
            relevant_output.append(line)


    # extract the address using regex
    ebp_match = re.search(r"\$1 = \(void \*\) (0x[0-9a-fA-F]+)", stdout)
    ebp_offset_match = re.search(r"\$2 = \(void \*\) (0x[0-9a-fA-F]+)", stdout)

    if ebp_offset_match:
        return ebp_offset_match.group(1)
    elif ebp_match:
        ebp_value = int(ebp_match.group(1), 16)
        calculated_address = ebp_value - int(buf_size_hex, 16)
        return hex(calculated_address)
    else:
        raise ValueError("Failed to retrieve address from GDB output.")


binary_name = "./vuln"
buffer_size = 116
buffer_size_hex = "0x6c"

result_address = find_address(binary_name, buffer_size, buffer_size_hex)
print(result_address)
