import sys
import os
import binascii

def extract_shellcode_after_nop_sled(pid, min_nop_sled_length=16, max_shellcode_length=256):
    try:
        with open(f"/proc/{pid}/maps", 'r') as maps_file:
            mappings = maps_file.readlines()

        stack_mapping = None
        for mapping in mappings:
            if '[stack]' in mapping:
                stack_mapping = mapping
                break

        if not stack_mapping:
            return None

        address_parts = stack_mapping.split()
        start, end = [int(x, 16) for x in address_parts[0].split('-')]

        with open(f"/proc/{pid}/mem", 'rb') as mem_file:
            mem_file.seek(start)
            stack_data = mem_file.read(end - start)

        first_candidate = find_first_nop_sled_shellcode(
            stack_data,
            min_nop_sled_length,
            max_shellcode_length
        )

        return first_candidate['hex_shellcode'] if first_candidate else None

    except Exception:
        return None

def find_first_nop_sled_shellcode(stack_data, min_nop_sled_length, max_shellcode_length):
    NOP = b'\x90'

    for i in range(len(stack_data) - min_nop_sled_length):
        if all(stack_data[j] == NOP[0] for j in range(i, i + min_nop_sled_length)):
            shellcode_start = i + min_nop_sled_length
            shellcode_end = min(shellcode_start + max_shellcode_length, len(stack_data))

            shellcode = stack_data[shellcode_start:shellcode_end]

            return {
                'hex_shellcode': binascii.hexlify(shellcode).decode('utf-8'),
            }

    return None