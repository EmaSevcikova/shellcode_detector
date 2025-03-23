from pattern_utils import find_pattern


class PatternDetector:
    def __init__(self, pattern_manager):
        self.pattern_manager = pattern_manager

    def detect_shellcode(self, data, max_distance=100):
        """
        Detect shellcode by identifying specific combinations of patterns.
        Only reports shellcode when finding valid combinations, not individual components.

        Args:
            data: The binary data to analyze
            max_distance: Maximum distance between related patterns

        Returns:
            Tuple of (is_detected, architecture, reason, matched_combinations)
        """
        # Determine architecture
        architecture = self.pattern_manager.determine_architecture(data)
        reason = ""
        is_detected = False
        matched_combinations = []

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

        # Check for valid combinations of patterns in primary architecture
        is_match, combo_names = self.pattern_manager.match_combined_shellcode(
            data, architecture, max_distance, return_names=True)

        # Debug code to verify we're getting names back
        print(f"DEBUG: match_combined_shellcode returned is_match={is_match}, combo_names={combo_names}")

        if is_match:
            # Only consider it detected if we have actually identified specific combinations
            if combo_names:
                reason += f"Found combination of {architecture} shellcode components."
                is_detected = True
                matched_combinations.extend(combo_names)
            else:
                # If we have a match but no combination names, there's an issue with the naming
                # We'll create a generic name instead of returning nothing
                reason += f"Found {architecture} shellcode pattern combination (unnamed)."
                is_detected = True
                matched_combinations.append(f"unnamed_{architecture}_combination")
        # Try other architecture if primary didn't match
        elif architecture == "64bit":
            is_match, combo_names = self.pattern_manager.match_combined_shellcode(
                data, "32bit", max_distance, return_names=True)

            # Debug code
            print(f"DEBUG: match_combined_shellcode for 32bit returned is_match={is_match}, combo_names={combo_names}")

            if is_match:
                architecture = "32bit"
                if combo_names:
                    reason += "Found combination of 32-bit shellcode components."
                    is_detected = True
                    matched_combinations.extend(combo_names)
                else:
                    # Same fallback for unnamed combinations
                    reason += "Found 32-bit shellcode pattern combination (unnamed)."
                    is_detected = True
                    matched_combinations.append("unnamed_32bit_combination")

        # Only collect and report individual components if no shellcode was detected, for informational purposes
        if not is_detected:
            component_matches = []
            for category, patterns in self.pattern_manager.behavior_patterns[architecture].items():
                if category != "specific" and any(find_pattern(data, p) != -1 for p in patterns):
                    component_matches.append(category)

            if component_matches:
                reason += f"Found individual components: {', '.join(component_matches)}. Not sufficient for shellcode detection."

        return (is_detected, architecture, reason, matched_combinations)