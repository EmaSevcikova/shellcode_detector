import subprocess
import os
import time
import signal
import sys
import threading

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


def log_stream(stream, prefix):
    """Log output from a stream with a prefix"""
    for line in iter(stream.readline, ''):
        if not line:
            break
        print(f"{prefix}: {line.strip()}")
        if "pid=" in line:
            # Extract PID when it appears in output
            pid_start = line.find("pid=") + 4
            pid_end = line.find("]", pid_start)
            if pid_start > 4 and pid_end > pid_start:
                try:
                    pid = int(line[pid_start:pid_end])
                    print(f"[+] Detected process PID: {pid}")
                    return pid
                except ValueError:
                    pass
    return None

def find_pid_with_pgrep(binary_path):
    """Find process PID using pgrep"""
    try:
        binary_name = os.path.basename(binary_path)
        pgrep_output = subprocess.check_output(["pgrep", binary_name]).decode().strip()
        if pgrep_output:
            # Take the first PID if multiple are found
            pid = int(pgrep_output.split('\n')[0])
            print(f"[+] Found PID using pgrep: {pid}")
            return pid
        return None
    except subprocess.CalledProcessError:
        return None
    except Exception as e:
        print(f"[!] Error using pgrep: {e}")
        return None


def extract_pid_from_info_proc(gdb_process):
    """
    Extract PID from GDB's 'info proc' command output
    """
    print("[*] Extracting PID using 'info proc'...")

    try:
        # Write the info proc command to GDB
        gdb_process.stdin.write("info proc\n")
        gdb_process.stdin.flush()

        # Give GDB time to process the command
        time.sleep(1)

        # Read from GDB's stdout to get the output of info proc
        output = ""

        # Create a temporary file to capture GDB output
        temp_output_file = "gdb_output_temp.txt"

        # Send command to redirect output to file
        gdb_process.stdin.write(f"set logging file {temp_output_file}\n")
        gdb_process.stdin.write("set logging on\n")
        gdb_process.stdin.write("info proc\n")
        gdb_process.stdin.write("set logging off\n")
        gdb_process.stdin.flush()

        # Give GDB time to create and write to the file
        time.sleep(2)

        # Read from the temporary file
        if os.path.exists(temp_output_file):
            with open(temp_output_file, 'r') as f:
                output = f.read()

            # Clean up the temporary file
            os.remove(temp_output_file)

        # Parse the PID from the output
        # Example output line: "process 12345"
        for line in output.split('\n'):
            if "process" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "process" and i + 1 < len(parts):
                        try:
                            pid = int(parts[i + 1])
                            print(f"[+] Found PID from 'info proc': {pid}")
                            return pid
                        except ValueError:
                            pass

        print("[!] Could not extract PID from 'info proc' output")
        return None

    except Exception as e:
        print(f"[!] Error extracting PID from 'info proc': {e}")
        return None

def run_gdb_process(binary_path, payload):
    """
    Run the binary in GDB with monitoring and return the PID
    """
    print("[*] Preparing GDB commands...")

    # Create GDB commands with the correct path to ret_addr_monitor.py
    gdb_commands = f"""
    file {binary_path}
    set disassemble-next-line on
    source anomaly_detector/ret_addr_monitor.py
    break func
    monitor-ret func
    run {payload}
    """

    print("[*] GDB commands prepared:")
    print(gdb_commands)

    print("[*] Starting GDB process...")

    # Start GDB in the background
    process = subprocess.Popen(
        ["gdb", "-q"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # Line buffered
    )

    print("[*] GDB process started. Setting up logging threads...")

    stdout_thread = threading.Thread(
        target=lambda: log_stream(process.stdout, "GDB stdout"),
        daemon=True
    )
    stderr_thread = threading.Thread(
        target=lambda: log_stream(process.stderr, "GDB stderr"),
        daemon=True
    )

    stdout_thread.start()
    stderr_thread.start()

    print("[*] Logging threads started. Sending commands to GDB...")

    # Send commands to GDB
    try:
        process.stdin.write(gdb_commands)
        process.stdin.flush()
        print("[*] Commands sent to GDB.")
    except Exception as e:
        print(f"[!] Error sending commands to GDB: {e}")

    # Give GDB time to start and execute commands
    print("[*] Waiting for GDB to process commands...")
    time.sleep(3)

    # Extract PID using our new function
    pid = extract_pid_from_info_proc(process)

    # If the primary method fails, fall back to pgrep as a secondary method
    if pid is None:
        print("[!] Couldn't determine PID using 'info proc', trying pgrep...")
        pid = find_pid_with_pgrep(binary_path)

    if pid:
        print(f"[+] Process running with PID: {pid}")
    else:
        print("[!] Failed to find process PID")

    return process, pid


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
    print(f"[*] Running behavior detection on PID {pid}")
    stack_shellcode = extract_shellcode_after_nop_sled(pid)

    if not stack_shellcode:
        print(f"No shellcode found in process {pid}")
        return False

    cleaned_shellcode = extract_shellcode(stack_shellcode)
    print(f"[*] Extracted shellcode: {cleaned_shellcode[:20]}...")

    if not cleaned_shellcode:
        print("Failed to extract clean shellcode")
        return False

    # Run emulation to detect behaviors
    return emulate_shellcode(cleaned_shellcode)


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

        # Wait for user input before terminating GDB
        input("\nPress Enter to terminate the debugged process...")

    finally:
        # Terminate GDB
        print("[*] Terminating GDB...")
        try:
            gdb_process.stdin.write("quit\ny\n")
            gdb_process.stdin.flush()
            gdb_process.wait(timeout=5)
        except:
            print("[!] Error while cleanly terminating GDB")

        # Make sure both GDB and the debugged process are terminated
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
                print(f"[*] Killed process with PID {pid}")
            except:
                print(f"[!] Could not kill process with PID {pid}")


if __name__ == "__main__":
    main()