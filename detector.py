import sys
import os

sys.path.append('./signature_analysis')
sys.path.append('./behavior_analysis')
sys.path.append('./anomaly_analysis')
sys.path.append('./reporting')

from gdb.process_manager import GdbProcessManager
from detectors.signature_detector import SignatureDetector
from detectors.behavior_detector import BehaviorDetector
from detectors.anomaly_detector import AnomalyDetector
from utils.cli import parse_arguments, get_payload
from reporting.report_generator import ReportHandler


def detector():
    """Main entry point for the exploit analyzer"""
    args = parse_arguments()
    if not args:
        return 1
    payload = get_payload(args)

    report_handler = ReportHandler()

    print("[*] Starting process under GDB with monitoring...")
    gdb_manager = GdbProcessManager(args.binary_path, payload, args.arch)
    pid = gdb_manager.run_gdb_process()

    if pid is None:
        print("[!] Failed to get PID of the debugged process. Exiting.")
        return 1

    print(f"[+] Process running with PID: {pid}")
    report_handler.set_target_info(pid, args.binary_path)

    try:
        print("\n*************** START SIGNATURE DETECTION ***************")
        sig_detector = SignatureDetector()
        sig_detected, detected_arch, detected_patterns, pattern_names = sig_detector.run_detection(pid)

        report_handler.record_signature_detection(
            sig_detected,
            len(detected_patterns) if detected_patterns else 0,
            detected_patterns,
            pattern_names
        )

        arch = args.arch
        if detected_arch:
            arch = detected_arch
            print(f"[+] Detected architecture: {arch}")
        else:
            print(f"[+] Using specified architecture: {arch}")
        print("\n*************** END SIGNATURE DETECTION ***************")

        print("\n*************** START BEHAVIOR DETECTION ***************")
        bhv_detector = BehaviorDetector()
        bhv_detected, syscalls, strings = bhv_detector.run_detection(pid, arch)

        report_handler.record_behavior_detection(bhv_detected, syscalls, strings)
        print("\n*************** END BEHAVIOR DETECTION ***************")

        print("\n*************** START ANOMALY DETECTION ***************")
        anomaly_detector = AnomalyDetector()
        anomaly_result = anomaly_detector.check_anomalies(gdb_manager.output_queue)
        anomaly_detected = anomaly_result["detected"]

        report_handler.record_anomaly_detection(anomaly_result)
        print("\n*************** END ANOMALY DETECTION ***************")

        print("\n[+] Detection Summary:")
        print(f"    Signature detection: {'DETECTED' if sig_detected else 'Not detected'}")
        print(f"    Behavior detection: {'DETECTED' if bhv_detected else 'Not detected'}")
        print(f"    Anomaly detection: {'DETECTED' if anomaly_detected else 'Not detected'}")

        detected_any = sig_detected or bhv_detected or anomaly_detected
        if detected_any:
            print("\n[!] ALERT: Malicious behavior detected!")
        else:
            print("\n[*] No malicious behavior detected.")

        report_handler.set_final_status(detected_any)
        report_handler.save_report(args.output)

        if not args.interactive:
            print("\n[*] Entering interactive mode. Type 'exit' to quit.")
            while True:
                try:
                    cmd = input("GDB Command> ")
                    if cmd.lower() in ('exit', 'quit'):
                        break

                    gdb_manager.send_command(cmd)
                    if not anomaly_detected:
                        new_anomaly_result = anomaly_detector.check_anomalies(gdb_manager.output_queue)
                        if new_anomaly_result["detected"]:
                            anomaly_detected = True
                            report_handler.record_anomaly_detection(new_anomaly_result)
                            print("\n[+] Detection Summary Update:")
                            print(f"    Signature detection: {'DETECTED' if sig_detected else 'Not detected'}")
                            print(f"    Behavior detection: {'DETECTED' if bhv_detected else 'Not detected'}")
                            print(f"    Anomaly detection: DETECTED")
                            print("\n[!] ALERT: Malicious behavior detected!")
                except KeyboardInterrupt:
                    print("\n[*] Interrupted. Exiting interactive mode.")
                    break

    finally:
        gdb_manager.terminate()

    return 0
