import gdb


class ReturnMonitor:
    def __init__(self):
        self.func_name = None
        self.original_return_addr = None
        self.return_addr_location = None
        self.entry_bp = None
        self.watchpoint = None
        self.known_libraries = []

    def setup(self, func_name):
        self.func_name = func_name
        print(f"[*] Setting up return address monitoring for function: {self.func_name}")

        # clean up any existing breakpoints
        self.cleanup()

        # get a list of loaded libraries for validation
        self.load_library_ranges()

        # create and register the entry breakpoint
        self.entry_bp = EntryBreakpoint(self.func_name, self)

    def load_library_ranges(self):
        self.known_libraries = []
        try:
            libs_output = gdb.execute("info sharedlibrary", to_string=True)
            for line in libs_output.split('\n'):
                if line and not line.startswith("From") and not line.startswith("Shared"):
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            start = int(parts[0], 16)
                            end = int(parts[2], 16)
                            name = parts[3] if len(parts) > 3 else "unknown"
                            self.known_libraries.append((start, end, name))
                            print(f"[+] Added library: {hex(start)}-{hex(end)} {name}")
                        except (ValueError, IndexError):
                            pass

            try:
                info_files = gdb.execute("info files", to_string=True)
                for line in info_files.split('\n'):
                    if "Entry point:" in line:
                        parts = line.split()
                        entry_point = int(parts[-1], 16)
                        # use a range of 1MB around entry point
                        start = (entry_point // 0x100000) * 0x100000  # round down to nearest MB
                        end = start + 0x100000
                        self.known_libraries.append((start, end, "main_executable"))
                        print(f"[+] Added main executable range: {hex(start)}-{hex(end)}")
            except Exception as e:
                print(f"[!] Error adding main executable: {e}")

            print(f"[*] Loaded {len(self.known_libraries)} library ranges for validation")
        except Exception as e:
            print(f"[!] Error loading libraries: {e}")

    def setup_watchpoint(self):
        try:
            self.watchpoint = ReturnAddressWatchpoint(self.return_addr_location, self)
            print(f"[*] Watchpoint set on return address at 0x{self.return_addr_location:x}")
        except Exception as e:
            print(f"[!] Error setting watchpoint: {e}")

    def cleanup(self):
        if self.entry_bp:
            self.entry_bp.delete()
            self.entry_bp = None
        if self.watchpoint:
            self.watchpoint.delete()
            self.watchpoint = None

    def is_valid_address(self, address):
        # check if the address is within any known library range
        for start, end, name in self.known_libraries:
            if start <= address < end:
                return True, f"Valid library: {name}"
        return False, "Unknown memory region"

    def is_stack_address(self, address):
        # stack range directly from proc maps
        try:
            mappings = gdb.execute("info proc mappings", to_string=True)
            for line in mappings.split('\n'):
                if "[stack]" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        stack_start = int(parts[0], 16)
                        stack_end = int(parts[1], 16)
                        if stack_start <= address < stack_end:
                            return True, f"Stack region: {hex(stack_start)}-{hex(stack_end)}"
                        else:
                            return False, "Not in stack region"
        except Exception as e:
            print(f"[!] Error checking stack address: {e}")

        return False, "Unknown region"

class EntryBreakpoint(gdb.Breakpoint):
    def __init__(self, func_name, monitor):
        super(EntryBreakpoint, self).__init__(func_name, gdb.BP_BREAKPOINT)
        self.monitor = monitor
        self.silent = True

    def stop(self):
        frame = gdb.selected_frame()

        bp_value = int(frame.read_register("ebp"))

        # return address is stored at [ebp+4] in 32-bit
        self.monitor.return_addr_location = bp_value + 4  # +8 for 64-bit

        self.monitor.original_return_addr = int(
            gdb.parse_and_eval(f"*(unsigned int*)({self.monitor.return_addr_location})"))

        print(f"[+] Function entered: {self.monitor.func_name}")
        print(f"[+] Original return address: 0x{self.monitor.original_return_addr:x}")
        print(f"[+] Return address stored at: 0x{self.monitor.return_addr_location:x}")

        print("[+] Stack memory around return address:")
        gdb.execute(f"x/8wx {self.monitor.return_addr_location - 12}")

        self.monitor.setup_watchpoint()

        return False


class ReturnAddressWatchpoint(gdb.Breakpoint):
    def __init__(self, addr_location, monitor):
        super(ReturnAddressWatchpoint, self).__init__(
            f"*(unsigned int*)({addr_location})",
            gdb.BP_WATCHPOINT,
            gdb.WP_WRITE
        )
        self.monitor = monitor
        self.silent = True

    def stop(self):
        if not self.monitor.return_addr_location or not self.monitor.original_return_addr:
            return False

        current_return_addr = int(gdb.parse_and_eval(f"*(unsigned int*)({self.monitor.return_addr_location})"))

        if current_return_addr == self.monitor.original_return_addr:
            return False

        is_stack, region_info = self.monitor.is_stack_address(current_return_addr)

        if is_stack:
            # execution redirected to stack
            print("\n[!] ALERT: POTENTIAL EXPLOIT DETECTED - Return address modified to point to stack!")
            print(f"[!] Return address location: 0x{self.monitor.return_addr_location:x}")
            print(f"[!] Original return address: 0x{self.monitor.original_return_addr:x}")
            print(f"[!] Modified to: 0x{current_return_addr:x} {region_info}")

            print("[!] Instruction causing the modification:")
            print(f"=> {gdb.execute('x/i $pc', to_string=True).strip()}")

            print("[!] Current stack memory around return address:")
            gdb.execute(f"x/8wx {self.monitor.return_addr_location - 12}")

            # try to disassemble the new target address
            try:
                print("[!] Target location (potential shellcode):")
                gdb.execute(f"x/5i 0x{current_return_addr:x}")
            except:
                print("[!] Cannot disassemble target address - might be invalid")

            return True
        else:
            # print(f"[*] Return address modified (legitimate): 0x{current_return_addr:x}")
            return False


class MonitorRetCommand(gdb.Command):
    def __init__(self):
        super(MonitorRetCommand, self).__init__("monitor-ret", gdb.COMMAND_USER)
        self.monitor = ReturnMonitor()

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if not args:
            print("[!] Error: Please specify a function name")
            print("[*] Usage: monitor-ret function_name")
            return

        func_name = args[0]
        self.monitor.setup(func_name)


# Simple command to check current return address
class CheckRetCommand(gdb.Command):
    def __init__(self):
        super(CheckRetCommand, self).__init__("check-ret", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        frame = gdb.selected_frame()

        bp_value = int(frame.read_register("ebp"))

        ret_addr_loc = bp_value + 4

        try:
            ret_addr = int(gdb.parse_and_eval(f"*(unsigned int*)({ret_addr_loc})"))
            print(f"[*] Current return address: 0x{ret_addr:x}")
            print(f"[*] Return address location: 0x{ret_addr_loc:x}")

            print("[*] Stack memory around return address:")
            gdb.execute(f"x/8wx {ret_addr_loc - 12}")

        except Exception as e:
            print(f"[!] Error reading return address: {e}")


MonitorRetCommand()
CheckRetCommand()

print("[*] Return address monitoring script loaded")
print("[*] Usage: monitor-ret FUNCTION_NAME")
print("[*] This will detect the exact moment when the return address is modified")
print("[*] You can also use 'check-ret' at any time to see the current return address")