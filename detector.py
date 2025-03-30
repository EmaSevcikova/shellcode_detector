import subprocess
import os
import time
import signal
import sys
import threading
import queue

# Add detector modules to path
sys.path.append('./signature_detector')
sys.path.append('./behavior_detector')
sys.path.append('./anomaly_detector')

# Import signature detection modules
from signature_detector.memory_scanner import MemoryScanner
from signature_detector.pattern_manager import PatternManager
from signature_detector.pattern_detector import PatternDetector

# Import behavior detection modules
from behavior_detector.extract_stack import extract_shellcode_after_nop_sled
from behavior_detector.extract_shellcode import extract_shellcode
from behavior_detector.qiling_emulator import emulate_shellcode


def run_gdb_process(binary_path, payload):
    """
    Run the binary in GDB with monitoring and return the PID
    Uses Python GDB interface to reliably get the PID
    """
    print("[*] Preparing GDB commands...")

    # Start with basic setup commands - don't run the program yet
    gdb_commands = f"""
    file {binary_path}
    set disassemble-next-line on
    source anomaly_detector/ret_addr_monitor.py
    break func
    monitor-ret func
    """

    print("[*] GDB commands prepared")

    print("[*] Starting GDB process...")
    process = subprocess.Popen(
        ["gdb", "-q"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    print("[*] GDB process started")

    # Set up a buffer for output
    full_output = []

    # Function to read GDB output
    def read_output():
        while True:
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue

            line = line.strip()
            if line:
                print(f"GDB> {line}")
                full_output.append(line)

    # Start the output reader thread
    output_thread = threading.Thread(target=read_output)
    output_thread.daemon = True
    output_thread.start()

    # Send initial setup commands
    try:
        process.stdin.write(gdb_commands)
        process.stdin.flush()
        print("[*] Initial commands sent to GDB")
        time.sleep(2)  # Give time for commands to process
    except Exception as e:
        print(f"[!] Error sending commands to GDB: {e}")
        return process, None

    # Now run the program
    try:
        print("[*] Starting the target program in GDB...")
        process.stdin.write(f"run {payload}\n")
        process.stdin.write(f"print $ebp - 0x6c + 0x14\n")
        process.stdin.write(f"next\n")
        process.stdin.write(f"next\n")
        process.stdin.flush()
        time.sleep(3)  # Wait for the program to start
    except Exception as e:
        print(f"[!] Error starting program: {e}")
        return process, None

    # Get the PID explicitly after program is running
    pid = None

    try:
        print("[*] Requesting PID from GDB...")
        # Clear any previous output
        process.stdout.flush()
        full_output.clear()

        # Create a file to temporarily store the PID
        pid_file = "gdb_pid.txt"

        # Use Python GDB to write PID to file instead of stdout
        pid_command = f"""python
with open("{pid_file}", "w") as f:
    f.write(str(gdb.selected_inferior().pid))
end
"""
        process.stdin.write(pid_command)
        process.stdin.flush()
        time.sleep(1)

        # Read PID from file
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid_str = f.read().strip()
                try:
                    pid = int(pid_str)
                    print(f"[+] Got PID from file: {pid}")
                except ValueError:
                    print(f"[!] Invalid PID in file: {pid_str}")

            # Clean up
            os.remove(pid_file)
    except Exception as e:
        print(f"[!] Error getting PID: {e}")

    if pid is None or pid == 1:  # Extra check to avoid using PID 1
        print("[!] Failed to get valid PID or got system PID 1")
        return process, None

    return process, pid


def send_gdb_command(gdb_process, command):
    """
    Send a command to a running GDB process and flush the input
    """
    try:
        gdb_process.stdin.write(f"{command}\n")
        gdb_process.stdin.flush()
        print(f"[*] Sent GDB command: {command}")
        return True
    except Exception as e:
        print(f"[!] Error sending GDB command: {e}")
        return False

def run_signature_detection(pid):
    """
    Run signature-based detection on the process
    """
    print(f"[*] Running signature detection on PID {pid}")
    scanner = MemoryScanner(pid)
    pattern_manager = PatternManager("signature_detector/patterns")
    detector = PatternDetector(pattern_manager)

    memory_regions = scanner.scan_memory()
    detected = False

    for addr, data in memory_regions:
        # print(f"Analyzing region at address: {hex(addr)}, size: {len(data)} bytes")

        result = detector.detect_shellcode(data)
        is_detected, architecture, reason, matched_combinations = result

        if is_detected:
            detected = True
            print(f"[!] Potential shellcode detected at address: {hex(addr)}")
            print(f"    Architecture: {architecture}")
            print(f"    Reason: {reason}")
            if matched_combinations:
                print(f"    Matched pattern combinations: {', '.join(matched_combinations)}")
            else:
                print(f"    WARNING: No specific combinations identified despite detection")

    return detected


def run_behavior_detection(pid):
    """
    Run behavior-based detection on the process
    """
    detected = False
    print(f"[*] Running behavior detection on PID {pid}")
    stack_shellcode = extract_shellcode_after_nop_sled(pid)

    if not stack_shellcode:
        print(f"No shellcode found in process {pid}")
        return detected

    cleaned_shellcode = extract_shellcode(stack_shellcode)
    print(f"[*] Extracted shellcode: {cleaned_shellcode[:20]}...")

    if not cleaned_shellcode:
        print("Failed to extract clean shellcode")
        return detected

    # Run emulation to detect behaviors
    emulate_shellcode(cleaned_shellcode)
    detected = True
    return detected


def main():
    # Configuration
    binary_path = input("Enter path to binary: ")

    # Handle payload
    payload_type = input("Enter payload type (string (s)/python (p)): ").lower()
    if payload_type == "p":
        payload_script = input("Enter payload script path: ")
        payload = f"$(python3 {payload_script})"
    else:
        payload = input("Enter payload string: ")

    # Run the process in GDB
    print("[*] Starting process under GDB with monitoring...")
    gdb_process, pid = run_gdb_process(binary_path, payload)

    if pid is None:
        print("[!] Failed to get PID of the debugged process. Exiting.")
        return

    print(f"[+] Process running with PID: {pid}")

    try:
        # Run signature detection
        sig_detected = run_signature_detection(pid)

        # Run behavior detection
        bhv_detected = run_behavior_detection(pid)

        # Print consolidated results
        print("\n[+] Detection Summary:")
        print(f"    Signature detection: {'DETECTED' if sig_detected else 'Not detected'}")
        print(f"    Behavior detection: {'DETECTED' if bhv_detected else 'Not detected'}")

        if sig_detected or bhv_detected:
            print("\n[!] ALERT: Malicious behavior detected!")
        else:
            print("\n[*] No malicious behavior detected.")

        # Interactive GDB mode
        print("\n[*] Entering interactive mode. Type 'exit' to quit.")
        while True:
            cmd = input("GDB Command> ")
            if cmd.lower() in ('exit', 'quit'):
                break
            send_gdb_command(gdb_process, cmd)

    finally:
        # Terminate GDB
        print("[*] Terminating GDB...")
        try:
            send_gdb_command(gdb_process, "quit")
            send_gdb_command(gdb_process, "y")  # Confirm quit
            gdb_process.wait(timeout=5)
        except:
            print("[!] Error while cleanly terminating GDB")
            # Force kill if needed
            try:
                gdb_process.kill()
            except:
                pass

        # Make sure the debugged process is terminated
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
                print(f"[*] Killed process with PID {pid}")
            except:
                print(f"[!] Could not kill process with PID {pid} (might already be terminated)")


if __name__ == "__main__":
    main()