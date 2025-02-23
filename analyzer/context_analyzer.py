
def parse_maps(pid):
    with open(f"/proc/{pid}/maps", "r") as f:
        return f.readlines()

def get_process_context(pid):
    with open(f"/proc/{pid}/status", "r") as f:
        return f.read()