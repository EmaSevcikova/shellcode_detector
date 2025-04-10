import json
from datetime import datetime
from typing import Dict, List, Optional, Any


class Report:
    def __init__(self):
        self.report = {
            "detection": {
                "status": "BENIGN",
                "timestamp": datetime.now().strftime("%Y-%m-%d")
            }
        }

    def set_target_info(self, process_id: int, executable: str) -> None:
        """Set target information for the report."""
        self.report["detection"]["target"] = {
            "process_id": process_id,
            "executable": executable
        }

    def set_exploit_details(self,
                            exploit_type: str,
                            vulnerable_function: str,
                            mechanism: str,
                            original_return_address: str,
                            modified_return_address: str,
                            stack_region: str) -> None:
        """
        Set exploit details if malicious detection.
        These details will only be included in the final report if status is MALICIOUS.
        """
        self.exploit_details = {
            "type": exploit_type,
            "vulnerable_function": vulnerable_function,
            "mechanism": mechanism,
            "original_return_address": original_return_address,
            "modified_return_address": modified_return_address,
            "stack_region": stack_region
        }

    def set_signature_detection(self,
                                result: str,
                                patterns_matched: Optional[int] = None,
                                pattern_combinations: Optional[List[str]] = None,
                                patterns: Optional[List[str]] = None) -> None:
        """
        Set signature detection results.
        Full details will only be included if result is DETECTED.
        """
        if "detection_methods" not in self.report["detection"]:
            self.report["detection"]["detection_methods"] = {}

        signature_detection = {"result": result}

        if result.upper() == "DETECTED":
            signature_detection["patterns_matched"] = patterns_matched
            signature_detection["pattern_combinations"] = pattern_combinations
            signature_detection["possible_shellcode"] = patterns

        self.report["detection"]["detection_methods"]["signature_detection"] = signature_detection

    def set_behavior_detection(self,
                               result: str,
                               syscalls: Optional[List[str]] = None,
                               string_occurrences: Optional[List[str]] = None) -> None:
        """
        Set behavior detection results.
        Full details will only be included if result is DETECTED.
        """
        if "detection_methods" not in self.report["detection"]:
            self.report["detection"]["detection_methods"] = {}

        behavior_detection = {"result": result}

        if result.upper() == "DETECTED":
            behavior_detection["syscalls"] = syscalls
            behavior_detection["string_occurrences"] = string_occurrences

        self.report["detection"]["detection_methods"]["behavior_detection"] = behavior_detection

    def set_anomaly_detection(self,
                              result: str,
                              findings: Optional[List[str]] = None) -> None:
        """
        Set anomaly detection results.
        Full details will only be included if result is DETECTED.
        """
        if "detection_methods" not in self.report["detection"]:
            self.report["detection"]["detection_methods"] = {}

        anomaly_detection = {"result": result}

        if result.upper() == "DETECTED":
            anomaly_detection["findings"] = findings

        self.report["detection"]["detection_methods"]["anomaly_detection"] = anomaly_detection

    def set_status(self, status: str) -> None:
        """Set overall detection status (BENIGN or MALICIOUS)."""
        self.report["detection"]["status"] = status

        # Add exploit details only if status is MALICIOUS
        if status.upper() == "MALICIOUS" and hasattr(self, 'exploit_details'):
            self.report["detection"]["exploit_details"] = self.exploit_details

    def generate_report(self) -> Dict[str, Any]:
        """Generate the final report dictionary."""
        return self.report

    def generate_json(self, pretty: bool = True) -> str:
        """Generate the JSON report as a string."""
        indent = 2 if pretty else None
        return json.dumps(self.report, indent=indent)

    def save_report(self, filename: str, pretty: bool = True) -> None:
        """Save the JSON report to a file."""
        with open(filename, 'w') as f:
            json.dump(self.report, f, indent=2 if pretty else None)
