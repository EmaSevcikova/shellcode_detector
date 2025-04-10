import sys

sys.path.append('./behavior_analysis')

from behavior_analysis.extract_stack import extract_shellcode_after_nop_sled
from behavior_analysis.extract_shellcode import extract_shellcode
from behavior_analysis.qiling_emulator import emulate_shellcode


class BehaviorDetector:
    """Analyzes process behavior to detect shellcode execution"""

    def run_detection(self, pid, arch):
        """
        Run behavior-based detection on the process

        Args:
            pid (int): Process ID to analyze
            arch (str): Architecture (32 or 64)

        Returns:
            tuple: (detected, syscalls, strings)
        """
        detected = False
        syscalls = None
        strings = None

        print(f"[*] Running behavior detection on PID {pid}")
        stack_shellcode = extract_shellcode_after_nop_sled(pid)

        if not stack_shellcode:
            print(f"No shellcode found in process {pid}")
            return detected, syscalls, strings

        cleaned_shellcode = extract_shellcode(stack_shellcode)
        print(f"[*] Extracted shellcode: {cleaned_shellcode[:20]}...")

        if not cleaned_shellcode:
            print("Failed to extract clean shellcode")
            return detected, syscalls, strings

        try:
            syscalls, strings = emulate_shellcode(cleaned_shellcode, arch)
            detected = True
        except Exception as e:
            print(f"Emulation error: {str(e)}")

        return detected, syscalls, strings