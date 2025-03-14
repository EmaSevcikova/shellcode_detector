from memory_scanner import MemoryScanner
from pattern_manager import PatternManager
from pattern_detector import PatternDetector


def main():
    pid = int(input("Enter the PID of the process to scan: "))
    # pid = 167058
    print(pid)
    scanner = MemoryScanner(pid)
    pattern_manager = PatternManager()
    detector = PatternDetector(pattern_manager)

    print("Scanning memory...")
    memory_regions = scanner.scan_memory()

    for addr, data in memory_regions:
        print(f"Analyzing region at address: {hex(addr)}, size: {len(data)} bytes")

        result = detector.detect_shellcode(data)
        is_detected, architecture, confidence, reason = result

        if is_detected:
            print(f"[!] Potential shellcode detected at address: {hex(addr)}")
            print(f"    Architecture: {architecture}")
            print(f"    Confidence: {confidence:.2f}")
            print(f"    Reason: {reason}")


if __name__ == "__main__":
    main()