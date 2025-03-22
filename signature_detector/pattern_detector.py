from pattern_manager import PatternManager
from pattern_utils import find_pattern


class PatternDetector:
    def __init__(self, pattern_manager):
        self.pattern_manager = pattern_manager

    def detect_shellcode(self, data, use_combined=True, max_distance=100):
        """
        Detect shellcode using both specific and combined pattern matching.
        Only reports shellcode when finding valid combinations, not just individual components.

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
        is_detected = False

        if architecture:
            if architecture == "mixed":
                reason += "Mixed 32-bit and 64-bit code detected. "
                # Default to 64-bit analysis for mixed code
                architecture = "64bit"
            else:
                reason += f"{architecture} code detected. "
        else:
            # Default to checking both architectures
            architecture = "64bit"  # Default, will check both

        # First check: Look for specific known shellcode patterns (highest confidence)
        specific_match = False

        if self.pattern_manager.match_specific_shellcode(data, architecture):
            specific_match = True
            confidence = 0.9  # High confidence for exact matches
            reason += f"Matched known {architecture} shellcode signature. "
            is_detected = True

        # If no specific match in primary architecture and architecture is uncertain, try the other
        elif architecture == "64bit" and self.pattern_manager.match_specific_shellcode(data, "32bit"):
            architecture = "32bit"
            confidence = 0.9
            reason += "Matched known 32-bit shellcode signature. "
            specific_match = True
            is_detected = True

        # Second check: Look for valid combinations of patterns (if not already detected)
        if use_combined and not specific_match:
            combined_match = False

            if self.pattern_manager.match_combined_shellcode(data, architecture, max_distance):
                combined_match = True
                confidence = 0.7  # Good confidence for combined patterns
                reason += f"Found combination of {architecture} shellcode components. "
                is_detected = True

            # Try other architecture if primary didn't match
            elif architecture == "64bit" and self.pattern_manager.match_combined_shellcode(data, "32bit", max_distance):
                architecture = "32bit"
                combined_match = True
                confidence = 0.7
                reason += "Found combination of 32-bit shellcode components. "
                is_detected = True

        # For debugging purposes, identify individual components
        # but explicitly mention they are not sufficient for detection
        component_matches = []

        for category, patterns in self.pattern_manager.behavior_patterns[architecture].items():
            if category != "specific" and any(find_pattern(data, p) != -1 for p in patterns):
                component_matches.append(category)

        if component_matches and not is_detected:
            reason += f"Found individual components: {', '.join(component_matches)}. Not sufficient for shellcode detection."
        elif component_matches:
            reason += f" Individual components found: {', '.join(component_matches)}."

        return (is_detected, architecture, confidence, reason)