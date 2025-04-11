import subprocess
import os
import time
import threading
import queue
import signal


class GdbProcessManager:
    """Manages the execution and communication with a GDB process"""

    def __init__(self, binary_path, function, payload, size, arch):
        self.binary_path = binary_path
        self.function = function
        self.payload = payload
        self.size = size
        self.arch = arch
        self.process = None
        self.pid = None
        self.output_queue = queue.Queue()
        self.full_output = []

    def run_gdb_process(self):
        """Run the binary in GDB with monitoring and return the PID"""
        print("[*] Preparing GDB commands...")

        if self.arch == "32":
            gdb_commands = f"""
            file {self.binary_path}
            source anomaly_analysis/ret_addr_monitor.py
            break {self.function}
            monitor-ret {self.function}
            """
        else:
            gdb_commands = f"""
            file {self.binary_path}
            source anomaly_analysis/ret_addr_monitor_64bit.py
            break {self.function}
            monitor-ret {self.function}
            """

        print("[*] GDB commands prepared")
        print("[*] Starting GDB process...")

        # Start GDB process
        self.process = subprocess.Popen(
            ["gdb", "-q"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        print("[*] GDB process started")

        output_thread = threading.Thread(target=self._read_output)
        output_thread.daemon = True
        output_thread.start()

        try:
            self.process.stdin.write(gdb_commands)
            self.process.stdin.flush()
            print("[*] Initial commands sent to GDB")
            time.sleep(2)
        except Exception as e:
            print(f"[!] Error sending commands to GDB: {e}")
            return None
        try:
            print("[*] Starting the target program in GDB...")
            self.process.stdin.write(f"run {self.payload}\n")
            if self.size:
                hex_size = hex(self.size)
                if self.arch == "64":
                    self.process.stdin.write(f"print $rbp - {hex_size} + 0x14\n")

                else:
                    self.process.stdin.write(f"print $ebp - {hex_size} + 0x14\n")
            self.process.stdin.write(f"next\n")
            self.process.stdin.write(f"next\n")
            self.process.stdin.flush()
            time.sleep(3)
        except Exception as e:
            print(f"[!] Error starting program: {e}")
            return None

        self.pid = self._get_pid()

        if self.pid is None or self.pid == 1:
            print("[!] Failed to get valid PID or got system PID 1")
            return None

        return self.pid

    def _read_output(self):
        """Thread function to read GDB output"""
        while True:
            line = self.process.stdout.readline()
            if not line:
                if self.process.poll() is not None:
                    break
                continue

            line = line.strip()
            if line:
                print(f"GDB> {line}")
                self.full_output.append(line)
                self.output_queue.put(line)

    def _get_pid(self):
        """Get the PID of the debugged process from GDB"""
        try:
            print("[*] Requesting PID from GDB...")
            self.process.stdout.flush()
            self.full_output.clear()

            pid_file = "gdb_pid.txt"

            pid_command = f"""python
with open("{pid_file}", "w") as f:
    f.write(str(gdb.selected_inferior().pid))
end
"""
            self.process.stdin.write(pid_command)
            self.process.stdin.flush()
            time.sleep(1)

            if os.path.exists(pid_file):
                with open(pid_file, 'r') as f:
                    pid_str = f.read().strip()
                    try:
                        pid = int(pid_str)
                        print(f"[+] Got PID from file: {pid}")
                        os.remove(pid_file)
                        return pid
                    except ValueError:
                        print(f"[!] Invalid PID in file: {pid_str}")
                        os.remove(pid_file)
        except Exception as e:
            print(f"[!] Error getting PID: {e}")

        return None

    def send_command(self, command):
        """Send a command to the running GDB process"""
        try:
            self.process.stdin.write(f"{command}\n")
            self.process.stdin.flush()
            print(f"[*] Sent GDB command: {command}")
            return True
        except Exception as e:
            print(f"[!] Error sending GDB command: {e}")
            return False

    def terminate(self):
        """Terminate the GDB process and the debugged process"""
        print("[*] Terminating GDB...")
        try:
            self.send_command("quit")
            self.send_command("y")
            self.process.wait(timeout=5)
        except:
            print("[!] Error while cleanly terminating GDB")
            try:
                self.process.kill()
            except:
                pass

        if self.pid:
            try:
                os.kill(self.pid, signal.SIGKILL)
                print(f"[*] Killed process with PID {self.pid}")
            except:
                print(f"[!] Could not kill process with PID {self.pid} (might already be terminated)")