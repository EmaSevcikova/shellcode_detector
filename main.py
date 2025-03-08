from memory_scanner import MemoryScanner
from shellcode_detector import ShellcodeDetector
from pattern_manager import PatternManager


def main():
    pid = int(input("Enter the PID of the process to scan: "))
    # pid = 167058
    print(pid)
    scanner = MemoryScanner(pid)
    pattern_manager = PatternManager()
    detector = ShellcodeDetector(pattern_manager)

    print("Scanning memory...")
    memory_regions = scanner.scan_memory()
    for addr, data in memory_regions:
        print("Addr: %d"%addr)
        if detector.detect_shellcode(data):
            print(f"Potential shellcode detected at address: {hex(addr)}")


if __name__ == "__main__":
    main()