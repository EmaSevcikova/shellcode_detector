from memory_scanner import MemoryScanner
from pattern_manager import PatternManager
from pattern_detector import PatternDetector


def main():
    pid = int(input("Enter the PID of the process to scan: "))
    print(pid)
    scanner = MemoryScanner(pid)
    pattern_manager = PatternManager("patterns")
    detector = PatternDetector(pattern_manager)

    # Print out the pattern combinations that we're looking for
    print("Loaded pattern combinations:")
    for arch, combinations in pattern_manager.pattern_combinations.items():
        print(f"  {arch}:")
        for combo in combinations:
            if isinstance(combo, dict):
                name = combo.get('name', 'unnamed')
                cats = combo.get('required_categories', [])
                print(f"    - {name}: {', '.join(cats)}")
            else:
                print(f"    - {', '.join(combo)}")

    print("Scanning memory...")
    memory_regions = scanner.scan_memory()

    for addr, data in memory_regions:
        print(f"Analyzing region at address: {hex(addr)}, size: {len(data)} bytes")

        result = detector.detect_shellcode(data)
        is_detected, architecture, reason, matched_combinations = result

        if is_detected:
            print(f"[!] Potential shellcode detected at address: {hex(addr)}")
            print(f"    Architecture: {architecture}")
            print(f"    Reason: {reason}")

            if matched_combinations:
                print(f"    Matched pattern combinations: {', '.join(matched_combinations)}")
            else:
                print(f"    WARNING: No specific combinations identified despite detection")


if __name__ == "__main__":
    main()