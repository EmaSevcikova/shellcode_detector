import re

def extract_shellcode(hex_input):
    hex_input = re.sub(r'[^0-9a-fA-F]', '', hex_input)

    try:
        nop_sled_match = re.search(r'(90+)', hex_input)
        if not nop_sled_match:
            return hex_input

        nop_sled_end = nop_sled_match.end()

        non_nop_match = re.search(r'[^90]', hex_input[nop_sled_end:])
        if not non_nop_match:
            return hex_input

        non_nop_start = nop_sled_end + non_nop_match.start()

        repeated_chars_match = re.search(r'(41+)', hex_input[non_nop_start:])
        if not repeated_chars_match:
            return hex_input[non_nop_start:]

        repeated_chars_start = non_nop_start + repeated_chars_match.start()

        return hex_input[non_nop_start:repeated_chars_start]

    except Exception:
        return None