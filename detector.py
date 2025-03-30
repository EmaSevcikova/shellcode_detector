import subprocess
import os
import time
import signal
import sys
import threading
import queue

sys.path.append('./signature_detector')
sys.path.append('./behavior_detector')
sys.path.append('./anomaly_detector')

from signature_detector.memory_scanner import MemoryScanner
from signature_detector.pattern_manager import PatternManager
from signature_detector.pattern_detector import PatternDetector

from behavior_detector.extract_stack import extract_shellcode_after_nop_sled
from behavior_detector.extract_shellcode import extract_shellcode
from behavior_detector.qiling_emulator import emulate_shellcode


def run_gdb_process(binary_path, payload):
    """
    Run the binary in GDB with monitoring and return the PID
    Uses Python GDB interface to reliably get the PID
    """
    print("[*] Preparing GDB commands...")

    gdb_commands = f"""
    file {binary_path}
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

    # buffer for output
    full_output = []

    # queue to pass data between threads
    output_queue = queue.Queue()

    #read GDB output
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
                output_queue.put(line)

    # start the output reader thread
    output_thread = threading.Thread(target=read_output)
    output_thread.daemon = True
    output_thread.start()

    # initial setup commands
    try:
        process.stdin.write(gdb_commands)
        process.stdin.flush()
        print("[*] Initial commands sent to GDB")
        time.sleep(2)
    except Exception as e:
        print(f"[!] Error sending commands to GDB: {e}")
        return process, None, output_queue

    try:
        print("[*] Starting the target program in GDB...")
        process.stdin.write(f"run {payload}\n")
        process.stdin.write(f"print $ebp - 0x6c + 0x14\n")
        process.stdin.write(f"next\n")
        process.stdin.write(f"next\n")
        process.stdin.flush()
        time.sleep(3)
    except Exception as e:
        print(f"[!] Error starting program: {e}")
        return process, None, output_queue

    # get PID
    pid = None

    try:
        print("[*] Requesting PID from GDB...")
        process.stdout.flush()
        full_output.clear()

        pid_file = "gdb_pid.txt"

        pid_command = f"""python
with open("{pid_file}", "w") as f:
    f.write(str(gdb.selected_inferior().pid))
end
"""
        process.stdin.write(pid_command)
        process.stdin.flush()
        time.sleep(1)

        # read PID
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid_str = f.read().strip()
                try:
                    pid = int(pid_str)
                    print(f"[+] Got PID from file: {pid}")
                except ValueError:
                    print(f"[!] Invalid PID in file: {pid_str}")

            os.remove(pid_file)
    except Exception as e:
        print(f"[!] Error getting PID: {e}")

    if pid is None or pid == 1:
        print("[!] Failed to get valid PID or got system PID 1")
        return process, None, output_queue

    return process, pid, output_queue


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

    try:
        emulate_shellcode(cleaned_shellcode)
        detected = True
    except Exception as e:
        print(f"Emulation error: {str(e)}")

    return detected


def check_anomaly_detection(output_queue):
    """
    Check for return address anomalies in GDB output
    """
    alert_message = "[!] ALERT: POTENTIAL EXPLOIT DETECTED - Return address modified to point to stack!"

    detected = False

    while not output_queue.empty():
        line = output_queue.get()
        if alert_message in line:
            detected = True
            print("[+] Anomaly detected: Return address modification detected")
            break

    return detected


def main():
    # configuration
    binary_path = input("Enter path to binary: ")

    # handle payload
    payload_type = input("Enter payload type (string (s)/python (p)): ").lower()
    if payload_type == "p":
        payload_script = input("Enter payload script path: ")
        payload = f"$(python3 {payload_script})"
    else:
        payload = input("Enter payload string: ")

    # run the process in GDB
    print("[*] Starting process under GDB with monitoring...")
    gdb_process, pid, output_queue = run_gdb_process(binary_path, payload)

    if pid is None:
        print("[!] Failed to get PID of the debugged process. Exiting.")
        return

    print(f"[+] Process running with PID: {pid}")

    try:
        sig_detected = run_signature_detection(pid)

        bhv_detected = run_behavior_detection(pid)

        anomaly_detected = check_anomaly_detection(output_queue)

        print("\n[+] Detection Summary:")
        print(f"    Signature detection: {'DETECTED' if sig_detected else 'Not detected'}")
        print(f"    Behavior detection: {'DETECTED' if bhv_detected else 'Not detected'}")
        print(f"    Anomaly detection: {'DETECTED' if anomaly_detected else 'Not detected'}")

        if sig_detected or bhv_detected or anomaly_detected:
            print("\n[!] ALERT: Malicious behavior detected!")
        else:
            print("\n[*] No malicious behavior detected.")

        # # Interactive GDB mode
        # print("\n[*] Entering interactive mode. Type 'exit' to quit.")
        # while True:
        #     cmd = input("GDB Command> ")
        #     if cmd.lower() in ('exit', 'quit'):
        #         break
        #
        #     # Send command to GDB
        #     send_gdb_command(gdb_process, cmd)
        #
        #     # Check for new anomalies after each command
        #     if not anomaly_detected:  # Only check if not already detected
        #         anomaly_detected = check_anomaly_detection(output_queue)
        #         if anomaly_detected:
        #             print("\n[+] Detection Summary Update:")
        #             print(f"    Signature detection: {'DETECTED' if sig_detected else 'Not detected'}")
        #             print(f"    Behavior detection: {'DETECTED' if bhv_detected else 'Not detected'}")
        #             print(f"    Anomaly detection: DETECTED")
        #             print("\n[!] ALERT: Malicious behavior detected!")

    finally:
        print("[*] Terminating GDB...")
        try:
            send_gdb_command(gdb_process, "quit")
            send_gdb_command(gdb_process, "y")
            gdb_process.wait(timeout=5)
        except:
            print("[!] Error while cleanly terminating GDB")
            try:
                gdb_process.kill()
            except:
                pass

        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
                print(f"[*] Killed process with PID {pid}")
            except:
                print(f"[!] Could not kill process with PID {pid} (might already be terminated)")


if __name__ == "__main__":
    main()