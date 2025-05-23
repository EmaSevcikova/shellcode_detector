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
            Tuple of (is_detected, architecture, reason, matched_combinations, matched_pattern_names)
        """
        # determine architecture
        architecture = self.pattern_manager.determine_architecture(data)
        reason = ""
        is_detected = False
        matched_combinations = []
        matched_pattern_names = []  # New list to store pattern names

        if architecture:
            if architecture == "mixed":
                reason += "Mixed 32-bit and 64-bit code detected. "
                architecture = "64bit"
            else:
                reason += f"{architecture} code detected. "
        else:
            architecture = "64bit"

        is_match, combo_names, pattern_names = self.pattern_manager.match_combined_shellcode(
            data, architecture, max_distance, return_names=True)

        if is_match and combo_names:
            reason += f"Found {architecture} shellcode pattern combinations."
            is_detected = True
            matched_combinations.extend(combo_names)
            matched_pattern_names.extend(pattern_names)  # Add matched pattern names
            print(f"Detection: POSITIVE - Found {len(combo_names)} pattern combinations")
            print(f"Pattern names: {', '.join(pattern_names)}")

        elif architecture == "64bit":
            is_match, combo_names, pattern_names = self.pattern_manager.match_combined_shellcode(
                data, "32bit", max_distance, return_names=True)

            if is_match and combo_names:
                architecture = "32bit"
                reason += "Found 32-bit shellcode pattern combinations."
                is_detected = True
                matched_combinations.extend(combo_names)
                matched_pattern_names.extend(pattern_names)  # Add matched pattern names
                print(f"Detection: POSITIVE - Found {len(combo_names)} pattern combinations")
                print(f"Pattern names: {', '.join(pattern_names)}")

        if not is_detected:
            print(f"Detection: NEGATIVE")

            component_matches = []
            component_pattern_names = []  # Track pattern names for component matches

            for category, patterns in self.pattern_manager.behavior_patterns[architecture].items():
                if category != "specific" and any(find_pattern(data, p) != -1 for p in patterns):
                    component_matches.append(category)

                    # Get pattern name for this component
                    pattern_name = self.pattern_manager.get_pattern_name_for_category(architecture, category)
                    if pattern_name and pattern_name not in component_pattern_names:
                        component_pattern_names.append(pattern_name)

            if component_matches:
                reason += f"Found individual components: {', '.join(component_matches)}. Not sufficient for shellcode detection."
                matched_pattern_names.extend(component_pattern_names)  # Include these pattern names too

        return (is_detected, architecture, reason, matched_combinations, matched_pattern_names)