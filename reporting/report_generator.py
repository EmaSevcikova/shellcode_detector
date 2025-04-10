from report import Report


class ReportHandler:
    """Handles creation and management of analysis reports"""

    def __init__(self):
        self.report_generator = Report()

    def set_target_info(self, pid, binary_path):
        """Set basic target information in the report"""
        self.report_generator.set_target_info(pid, binary_path)

    def record_signature_detection(self, detected, patterns_matched, pattern_combinations, patterns):
        """Record signature detection results"""
        self.report_generator.set_signature_detection(
            result="DETECTED" if detected else "NOT_DETECTED",
            patterns_matched=patterns_matched if patterns_matched else 0,
            pattern_combinations=pattern_combinations if pattern_combinations else [],
            patterns=patterns if patterns else []
        )

    def record_behavior_detection(self, detected, syscalls, strings):
        """Record behavior detection results"""
        self.report_generator.set_behavior_detection(
            result="DETECTED" if detected else "NOT_DETECTED",
            syscalls=syscalls,
            string_occurrences=strings
        )

    def record_anomaly_detection(self, anomaly_result):
        """Record anomaly detection results"""
        anomaly_detected = anomaly_result["detected"]

        if anomaly_detected:
            findings = [
                f"Original return address: {anomaly_result['original_return_address']}",
                f"Modified return address: {anomaly_result['modified_return_address']}",
                f"Stack region: {anomaly_result['stack_region']}"
            ]

            self.report_generator.set_anomaly_detection(
                result="DETECTED",
                findings=findings
            )

            self.report_generator.set_exploit_details(
                exploit_type="stack buffer overflow",
                vulnerable_function="func",
                mechanism="return address modification",
                original_return_address=anomaly_result['original_return_address'],
                modified_return_address=anomaly_result['modified_return_address'],
                stack_region=anomaly_result['stack_region']
            )
        else:
            self.report_generator.set_anomaly_detection(result="NOT_DETECTED")

    def set_final_status(self, detected_any):
        """Set the final status of the report"""
        if detected_any:
            self.report_generator.set_status("MALICIOUS")
        else:
            self.report_generator.set_status("BENIGN")

    def save_report(self, output_file):
        """Save the report to a file"""
        self.report_generator.save_report(output_file)
        print(f"\n[+] Report saved to {output_file}")