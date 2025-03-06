import re

class MemoryScanner:
    def __init__(self, pid):
        self.pid = pid

    def scan_memory(self):
        memory_regions = []
        maps_path = f"/proc/{self.pid}/maps"
        mem_path = f"/proc/{self.pid}/mem"

        with open(maps_path, "r") as maps:
            for line in maps:
                match = re.match(r"([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+..x", line)
                if match:
                    start, end = int(match[1], 16), int(match[2], 16)
                    print(f"Attempting to read region: {hex(start)}-{hex(end)}")
                    try:
                        with open(mem_path, "rb") as mem:
                            mem.seek(start)
                            data = mem.read(end - start)
                            memory_regions.append((start, data))
                            print(f"Successfully read region: {hex(start)}-{hex(end)}")
                    except IOError as e:
                        print(f"Failed to read region: {hex(start)}-{hex(end)}. Error: {e}")
                    except Exception as e:
                        print(f"Unexpected error reading region: {hex(start)}-{hex(end)}. Error: {e}")
        return memory_regions
