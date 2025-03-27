import sys
from extract_stack import extract_shellcode_after_nop_sled
from extract_shellcode import extract_shellcode
from qiling_emulator import emulate_shellcode


def main():
    if len(sys.argv) < 2:
        print("Usage: python shellcode_emulator.py <PID>")
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
    except ValueError:
        print("Error: PID must be an integer")
        sys.exit(1)

    stack_shellcode = extract_shellcode_after_nop_sled(pid)

    if not stack_shellcode:
        print(f"No shellcode found in process {pid}")
        sys.exit(1)

    cleaned_shellcode = extract_shellcode(stack_shellcode)
    print(f"[*] extracted shellcode: {cleaned_shellcode}")

    if not cleaned_shellcode:
        print("Failed to extract clean shellcode")
        sys.exit(1)

    emulate_shellcode(cleaned_shellcode)


if __name__ == '__main__':
    main()