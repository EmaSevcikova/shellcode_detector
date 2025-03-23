import re

# Memory protection constants
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE = 0x10
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_NOACCESS = 0x01

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000


class MemoryScanner:
    def __init__(self, pid):
        self.pid = pid

    def is_executable(self, protection):
        """Check if the memory region is executable."""
        return (protection & PAGE_EXECUTE_READWRITE) or (protection & PAGE_EXECUTE_READ) or (protection & PAGE_EXECUTE)

    def is_readable(self, protection):
        """Check if the memory region is readable."""
        return (protection & PAGE_READWRITE) or (protection & PAGE_READONLY)

    def is_normal_inaccessible(self, state, mapping_type, protection):
        """Check if the memory region is normally inaccessible."""
        if (state & MEM_COMMIT) == 0:
            return False
        if mapping_type != MEM_IMAGE and mapping_type != MEM_MAPPED and mapping_type != MEM_PRIVATE:
            return False
        if protection & PAGE_NOACCESS:
            return True
        return False

    def is_library(self, pathname):
        """Check if the memory region is a library file."""
        if not pathname:
            return False

        # Check if the pathname contains typical library patterns
        lib_patterns = [
            r'\.so(\.\d+)*$',  # Matches .so, .so.1, .so.1.2, etc.
            r'/lib/',  # Libraries in /lib/ directory
            r'/usr/lib/',  # Libraries in /usr/lib/ directory
        ]

        for pattern in lib_patterns:
            if re.search(pattern, pathname):
                return True

        return False

    def scan_memory(self):
        """Scan the memory of the process and return executable regions, excluding libraries."""
        memory_regions = []
        maps_path = f"/proc/{self.pid}/maps"
        mem_path = f"/proc/{self.pid}/mem"

        with open(maps_path, "r") as maps:
            for line in maps:
                # Parse the memory region line
                parts = line.split()
                if len(parts) < 5:
                    continue

                address_range = parts[0]
                permissions = parts[1]
                offset = int(parts[2], 16)
                dev = parts[3]
                inode = int(parts[4])
                pathname = parts[5] if len(parts) > 5 else ""

                # Extract start and end addresses
                start, end = map(lambda x: int(x, 16), address_range.split('-'))
                size = end - start

                # Parse permissions
                protection = 0
                if 'r' in permissions:
                    protection |= PAGE_READONLY
                if 'w' in permissions:
                    protection |= PAGE_READWRITE
                if 'x' in permissions:
                    protection |= PAGE_EXECUTE

                # Skip non-executable regions
                if not self.is_executable(protection):
                    continue

                # Skip library regions
                if self.is_library(pathname):
                    print(f"Skipping library region: {hex(start)}-{hex(end)} ({pathname})")
                    continue

                # Read the memory region
                print(f"Attempting to read executable region: {hex(start)}-{hex(end)}")
                try:
                    with open(mem_path, "rb") as mem:
                        mem.seek(start)
                        data = mem.read(size)
                        memory_regions.append((start, data))
                        print(f"Successfully read region: {hex(start)}-{hex(end)}")
                except IOError as e:
                    print(f"Failed to read region: {hex(start)}-{hex(end)}. Error: {e}")
                except Exception as e:
                    print(f"Unexpected error reading region: {hex(start)}-{hex(end)}. Error: {e}")

        return memory_regions