from execve_sh_patterns import *
from pattern_utils import *


class PatternManager:
    def __init__(self):
        # Architecture detection patterns
        self.architecture_patterns = {
            "32bit": arch_patterns_32,
            "64bit": arch_patterns_64
        }

        # Shellcode specific patterns
        self.shellcode_patterns = {
            "32bit": {
                "syscall": syscall_patterns_32,
                "execve_syscall": execve_syscall_num_patterns_32,
                "shell_string": shell_string_patterns_32,
            },
            "64bit": {
                "syscall": syscall_patterns_64,
                "execve_syscall": execve_syscall_num_patterns_64,
                "shell_string": shell_string_patterns_64,
                "stack_arg": stack_arg_patterns_64,
                "exit": exit_patterns_64,
                "specific": specific_signatures_64
            }
        }

    def determine_architecture(self, data):
        """
        Determine if code is 32-bit or 64-bit.
        Returns: "32bit", "64bit", or None if undetermined
        """
        # Count matches for each architecture
        count_32bit = 0
        count_64bit = 0

        for pattern in self.architecture_patterns["32bit"]:
            matches = find_all_patterns(data, pattern)
            count_32bit += len(matches)

        for pattern in self.architecture_patterns["64bit"]:
            matches = find_all_patterns(data, pattern)
            count_64bit += len(matches)

        # Decide based on count
        if count_32bit > 0 and count_64bit == 0:
            return "32bit"
        elif count_64bit > 0 and count_32bit == 0:
            return "64bit"
        elif count_64bit > count_32bit:
            return "64bit"
        elif count_32bit > count_64bit:
            return "32bit"
        elif count_32bit > 0:  # Equal counts but not zero
            return "mixed"
        else:
            return None

    def match_specific_shellcode(self, data, arch="64bit"):
        """Check for exact matches of known shellcode patterns"""
        patterns = self.shellcode_patterns.get(arch, {}).get("specific", [])
        if not patterns:
            return False

        for pattern in patterns:
            if find_pattern(data, pattern) != -1:
                print(pattern)
                return True
        return False

    def match_combined_shellcode(self, data, arch, max_distance=100):
        """
        Look for combinations of patterns that indicate shellcode.
        Returns True if patterns from multiple categories are found within max_distance.
        """
        patterns = self.shellcode_patterns.get(arch, {})
        if not patterns:
            return False

        # Look for combinations that strongly indicate shellcode
        pattern_combinations = []

        # Add architecture-specific combinations
        if arch == "32bit":
            pattern_combinations = [
                # Syscall + execve number + shell string
                [patterns.get("syscall", []),
                 patterns.get("execve_syscall", []),
                 patterns.get("shell_string", [])]
            ]
        else:  # 64bit or default
            pattern_combinations = [
                # Syscall + execve number + shell string
                [patterns.get("syscall", []),
                 patterns.get("execve_syscall", []),
                 patterns.get("shell_string", [])],

                # Shell string + stack arg manipulation + syscall
                [patterns.get("shell_string", []),
                 patterns.get("stack_arg", []),
                 patterns.get("syscall", [])],

                # Exit + syscall (often in shellcode)
                [patterns.get("exit", []),
                 patterns.get("syscall", [])]
            ]

        for combination in pattern_combinations:
            if find_pattern_sets(data, combination, max_distance):
                print(combination)
                return True

        return False