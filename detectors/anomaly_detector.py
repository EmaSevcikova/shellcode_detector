class AnomalyDetector:
    """Detects anomalies in program execution, such as return address modifications"""

    def check_anomalies(self, output_queue):
        """
        Check for return address anomalies in GDB output

        Args:
            output_queue (Queue): Queue containing GDB output lines

        Returns:
            dict: Dictionary containing detection results
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