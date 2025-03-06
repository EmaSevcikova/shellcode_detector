from memory_scanner import MemoryScanner


def main():
    pid = int(input("Enter the PID of the process to scan: "))
    print(pid)
    scanner = MemoryScanner(pid)


    print("Scanning memory...")
    memory_regions = scanner.scan_memory()
    for addr, data in memory_regions:
        print("Addr: %d"%addr)


if __name__ == "__main__":
    main()