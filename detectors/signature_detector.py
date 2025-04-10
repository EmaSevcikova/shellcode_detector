import sys

sys.path.append('./signature_analysis')

from signature_analysis.memory_scanner import MemoryScanner
from signature_analysis.pattern_manager import PatternManager
from signature_analysis.pattern_detector import PatternDetector


class SignatureDetector:
    """Handles signature-based detection of shellcode in memory"""

    def __init__(self):
        self.pattern_manager = PatternManager("signature_analysis/patterns")
        self.detector = PatternDetector(self.pattern_manager)

    def run_detection(self, pid):
        """
        Run signature-based detection on the process memory

        Args:
            pid (int): Process ID to analyze

        Returns:
            tuple: (detected, architecture, combinations, pattern_names)
        """
        print(f"[*] Running signature detection on PID {pid}")
        scanner = MemoryScanner(pid)

        memory_regions = scanner.scan_memory()
        detected = False
        combinations = []
        pattern_names = []
        architecture = None

        for addr, data in memory_regions:
            result = self.detector.detect_shellcode(data)
            is_detected, detected_arch, reason, matched_combinations, matched_pattern_names = result

            if is_detected:
                detected = True
                architecture = detected_arch
                print(f"[!] Potential shellcode detected at address: {hex(addr)}")
                print(f"    Architecture: {architecture}")
                print(f"    Reason: {reason}")

                if matched_combinations:
                    print(f"    Matched pattern combinations: {', '.join(matched_combinations)}")
                    combinations.extend(matched_combinations)
                else:
                    print(f"    WARNING: No specific combinations identified despite detection")

                if matched_pattern_names:
                    print(f"    Matched shellcode types: {', '.join(matched_pattern_names)}")
                    # Add unique pattern names to the list
                    for name in matched_pattern_names:
                        if name not in pattern_names:
                            pattern_names.append(name)

        architecture_num = architecture.replace("bit", "") if architecture else None

        return detected, architecture_num, combinations, pattern_names