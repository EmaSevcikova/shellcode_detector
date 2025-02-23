# main.py
from analyzer.static_analyzer import load_rules, scan_memory
from analyzer.dynamic_analyzer import emulate_code
from utils.extract_executable import extract_executable_memory
from utils.memory_utils import capture_snapshot


def analyze_process(pid):
    # Capture snapshot
    capture_snapshot(pid, "snapshot.bin")

    # Static analysis
    print("[*] Loading rules")
    rules = load_rules("shellcode_rules.yar")
    print("[*] Opening memory dump")
    with open("snapshots/snapshot.bin.30716", "rb") as f:
        memory_dump = f.read()
    static_results = scan_memory(memory_dump, rules)

    # Example usage
    executable = extract_executable_memory("snapshots/snapshot.bin.30716", "extracted_code.bin")
    # Dynamic analysis
    # Load extracted executable memory from a file
    with open("extracted_code.bin", "rb") as f:
        code = f.read()

    # Run emulation with shellcode detection
    if emulate_code(code):
        print("[!] Warning: Shellcode detected in process memory!")
    else:
        print("[+] No shellcode found.")

    # Output results
    print("[*] Static Analysis Results:", static_results)


if __name__ == '__main__':
    analyze_process(31030)
