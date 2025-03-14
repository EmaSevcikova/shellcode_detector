from pattern_manager import PatternManager
from pattern_utils import find_pattern


class PatternDetector:
    def __init__(self, pattern_manager):
        self.pattern_manager = pattern_manager

    def detect_shellcode(self, data, use_combined=True, max_distance=100):
        """
        Detect shellcode using both specific and combined pattern matching.

        Args:
            data: The binary data to analyze
            use_combined: Whether to use combined pattern matching
            max_distance: Maximum distance between related patterns

        Returns:
            Tuple of (is_detected, architecture, confidence, reason)
        """
        # Determine architecture
        architecture = self.pattern_manager.determine_architecture(data)
        confidence = 0
        reason = ""

        if architecture:
            if architecture == "mixed":
                reason += "Mixed 32-bit and 64-bit code detected. "
                confidence += 0.1
                # Default to 64-bit analysis for mixed code
                architecture = "64bit"
            else:
                reason += f"{architecture} code detected. "
                confidence += 0.2
        else:
            # Default to checking both architectures
            architecture = "64bit"  # Default, will check both

        # Check for specific shellcode signatures (high confidence)
        specific_match = False

        if self.pattern_manager.match_specific_shellcode(data, architecture):
            specific_match = True
            confidence += 0.8
            reason += f"Matched known {architecture} shellcode signature. "

        # If no specific match in primary architecture and architecture is uncertain, try the other
        if not specific_match and architecture == "64bit" and self.pattern_manager.match_specific_shellcode(data,
                                                                                                            "32bit"):
            architecture = "32bit"
            confidence += 0.8
            reason += "Matched known 32-bit shellcode signature. "
            specific_match = True

        # Check for combined patterns if enabled
        if use_combined and not specific_match:
            if self.pattern_manager.match_combined_shellcode(data, architecture, max_distance):
                confidence += 0.6
                reason += f"Found combination of {architecture} shellcode components. "
            elif architecture == "64bit" and self.pattern_manager.match_combined_shellcode(data, "32bit", max_distance):
                architecture = "32bit"
                confidence += 0.6
                reason += "Found combination of 32-bit shellcode components. "

        # Simple pattern matching for individual components
        component_matches = []

        for category, patterns in self.pattern_manager.behavior_patterns[architecture].items():
            if category != "specific" and any(find_pattern(data, p) != -1 for p in patterns):
                component_matches.append(category)
                confidence += self.pattern_manager.component_confidence.get(category, 0.1)

        if component_matches:
            reason += f"Found individual components: {', '.join(component_matches)}."

        is_detected = confidence >= 0.5

        return (is_detected, architecture, confidence, reason)


# Example usage
# def main():
#     # Example shellcode bytes (64-bit)
#     shellcode_64 = bytes([
#         0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,
#         0x50, 0x54, 0x5f, 0x31, 0xc0, 0x50, 0xb0, 0x3b, 0x54, 0x5a,
#         0x54, 0x5e, 0x0f, 0x05
#     ])
#
#     # Example shellcode bytes (32-bit)
#     shellcode_32 = bytes([
#         0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f,
#         0x62, 0x69, 0x6e, 0x89, 0xe3, 0x50, 0x89, 0xe2, 0x53, 0x89,
#         0xe1, 0xb0, 0x0b, 0xcd, 0x80
#     ])
#
#     pm = PatternManager("patterns")
#     detector = ShellcodeDetector(pm)
#
#     print("Testing 64-bit shellcode:")
#     result_64 = detector.detect_shellcode(shellcode_64)
#     print(f"Detection: {result_64[0]}")
#     print(f"Architecture: {result_64[1]}")
#     print(f"Confidence: {result_64[2]:.2f}")
#     print(f"Reason: {result_64[3]}")
#
#     print("\nTesting 32-bit shellcode:")
#     result_32 = detector.detect_shellcode(shellcode_32)
#     print(f"Detection: {result_32[0]}")
#     print(f"Architecture: {result_32[1]}")
#     print(f"Confidence: {result_32[2]:.2f}")
#     print(f"Reason: {result_32[3]}")
#
#
# if __name__ == "__main__":
#     main()