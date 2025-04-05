import subprocess
import os
import time
import signal
import sys
import threading
import queue
import argparse
from report import ExploitReportGenerator

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
    combinations = []
    pattern_names = []  # New list to track pattern names

    for addr, data in memory_regions:
        # print(f"Analyzing region at address: {hex(addr)}, size: {len(data)} bytes")

        result = detector.detect_shellcode(data)
        is_detected, architecture, reason, matched_combinations, matched_pattern_names = result

        if is_detected:
            detected = True
            print(f"[!] Potential shellcode detected at address: {hex(addr)}")
            print(f"    Architecture: {architecture}")
            print(f"    Reason: {reason}")

            if matched_combinations:
                print(f"    Matched pattern combinations: {', '.join(matched_combinations)}")
                combinations.extend(matched_combinations)
            else:
                print(f"    WARNING: No specific combinations identified despite detection")

            if matched_pattern_names:
                print(f"    Matched shellcode types: {', '.join(matched_pattern_names)}")
                # Add unique pattern names to the list
                for name in matched_pattern_names:
                    if name not in pattern_names:
                        pattern_names.append(name)

    architecture_num = architecture.replace("bit", "")
    return detected, architecture_num, combinations, pattern_names


def run_behavior_detection(pid, arch):
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
        emulate_shellcode(cleaned_shellcode, arch)
        detected = True
    except Exception as e:
        print(f"Emulation error: {str(e)}")

    return detected


def check_anomaly_detection(output_queue):
    """
    Check for return address anomalies in GDB output and extract relevant information
    """
    alert_message = "[!] ALERT: POTENTIAL EXPLOIT DETECTED - Return address modified to point to stack!"

    detected = False
    original_return_address = None
    modified_return_address = None
    stack_region = None

    while not output_queue.empty():
        line = output_queue.get()

        if alert_message in line:
            detected = True
            print("[+] Anomaly detected: Execution from stack region detected")

        elif "[!] Original return address:" in line:
            original_return_address = line.split(":")[-1].strip()

        elif "[!] Modified to:" in line:
            parts = line.split()
            modified_return_address = parts[3]
            stack_region = parts[-1]

    return {
        "detected": detected,
        "original_return_address": original_return_address,
        "modified_return_address": modified_return_address,
        "stack_region": stack_region
    }


def main():
    # Configure argument parser
    parser = argparse.ArgumentParser(description="Binary Analysis Tool")
    parser.add_argument("binary_path", help="Path to the binary to analyze")
    parser.add_argument("-a", "--arch", choices=["32", "64"], required=True,
                        help="Architecture: 32 or 64 bit")
    parser.add_argument("-o", "--output", help="Output file for the report (JSON)", default="exploit_report.json")

    # Payload group - ensure only one can be used
    payload_group = parser.add_mutually_exclusive_group(required=True)
    payload_group.add_argument("-s", "--string", help="Payload as a string")
    payload_group.add_argument("-p", "--python", help="Path to Python script that generates payload")

    # Optional arguments
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--interactive", action="store_false", help="Enable interactive GDB mode")

    args = parser.parse_args()

    if not os.path.isfile(args.binary_path):
        print(f"[!] Error: Binary file '{args.binary_path}' not found")
        return 1

    report_generator = ExploitReportGenerator()

    # Handle payload
    if args.python:
        if not os.path.isfile(args.python):
            print(f"[!] Error: Python script '{args.python}' not found")
            return 1
        payload = f"$(python3 {args.python})"
    else:
        payload = args.string

    # arch = "x86" if args.arch == "32" else "x86_64"
    arch = args.arch

    # Run the process in GDB
    print("[*] Starting process under GDB with monitoring...")
    gdb_process, pid, output_queue = run_gdb_process(args.binary_path, payload)

    if pid is None:
        print("[!] Failed to get PID of the debugged process. Exiting.")
        return 1

    print(f"[+] Process running with PID: {pid}")

    report_generator.set_target_info(pid, args.binary_path)

    try:
        print("\n*************** START SIGNATURE DETECTION ***************")
        sig_detected, detected_arch, detected_patterns, pattern_names = run_signature_detection(pid)

        report_generator.set_signature_detection(
            result="DETECTED" if sig_detected else "NOT_DETECTED",
            patterns_matched=len(detected_patterns) if detected_patterns else 0,
            pattern_combinations=detected_patterns if detected_patterns else [],
            patterns=pattern_names if pattern_names else []
        )

        if detected_arch:
            arch = detected_arch
            print(f"[+] Detected architecture: {arch}")
        else:
            print(f"[+] Using specified architecture: {arch}")
        print("\n*************** END SIGNATURE DETECTION ***************")

        print("\n*************** START BEHAVIOR DETECTION ***************")
        bhv_detected = run_behavior_detection(pid, arch)

        # TODO
        report_generator.set_behavior_detection(
            result="DETECTED" if bhv_detected else "NOT_DETECTED"
        )

        print("\n*************** END BEHAVIOR DETECTION ***************")

        print("\n*************** START ANOMALY DETECTION ***************")
        anomaly_result = check_anomaly_detection(output_queue)
        anomaly_detected = anomaly_result["detected"]

        if anomaly_detected:
            findings = [
                f"Original return address: {anomaly_result['original_return_address']}",
                f"Modified return address: {anomaly_result['modified_return_address']}",
                f"Stack region: {anomaly_result['stack_region']}"
            ]

            report_generator.set_anomaly_detection(
                result="DETECTED",
                findings=findings
            )

            report_generator.set_exploit_details(
                exploit_type="stack buffer overflow",
                vulnerable_function="func",
                mechanism="return address modification",
                original_return_address=anomaly_result['original_return_address'],
                modified_return_address=anomaly_result['modified_return_address'],
                stack_region=anomaly_result['stack_region']
            )
        else:
            report_generator.set_anomaly_detection(result="NOT_DETECTED")

        print("\n*************** END ANOMALY DETECTION ***************")

        print("\n[+] Detection Summary:")
        print(f"    Signature detection: {'DETECTED' if sig_detected else 'Not detected'}")
        print(f"    Behavior detection: {'DETECTED' if bhv_detected else 'Not detected'}")
        print(f"    Anomaly detection: {'DETECTED' if anomaly_detected else 'Not detected'}")

        if sig_detected or bhv_detected or anomaly_detected:
            print("\n[!] ALERT: Malicious behavior detected!")
            report_generator.set_status("MALICIOUS")
        else:
            print("\n[*] No malicious behavior detected.")
            report_generator.set_status("BENIGN")

        # Save the report
        report_generator.save_report(args.output)
        print(f"\n[+] Report saved to {args.output}")

        # interactive GDB mode
        if not args.interactive:
            print("\n[*] Entering interactive mode. Type 'exit' to quit.")
            while True:
                try:
                    cmd = input("GDB Command> ")
                    if cmd.lower() in ('exit', 'quit'):
                        break

                    send_gdb_command(gdb_process, cmd)

                    if not anomaly_detected:
                        anomaly_detected = check_anomaly_detection(output_queue)
                        if anomaly_detected:
                            print("\n[+] Detection Summary Update:")
                            print(f"    Signature detection: {'DETECTED' if sig_detected else 'Not detected'}")
                            print(f"    Behavior detection: {'DETECTED' if bhv_detected else 'Not detected'}")
                            print(f"    Anomaly detection: DETECTED")
                            print("\n[!] ALERT: Malicious behavior detected!")
                except KeyboardInterrupt:
                    print("\n[*] Interrupted. Exiting interactive mode.")
                    break

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

    return 0


if __name__ == "__main__":
    sys.exit(main())