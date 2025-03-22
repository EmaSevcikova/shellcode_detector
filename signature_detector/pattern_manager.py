from pattern_utils import *
from pattern_loader import PatternLoader
from signature_detector.patterns.arch_patterns import architecture_patterns
from pattern_decision_tree import build_pattern_decision_tree


class PatternManager:
    def __init__(self, patterns_dir="patterns"):
        self.loader = PatternLoader(patterns_dir)
        self.loader.load_patterns()

        # Use imported architecture patterns directly
        self.architecture_patterns = architecture_patterns

        # Initialize collections for behavior patterns only
        self.behavior_patterns = {
            "32bit": {},
            "64bit": {}
        }

        self.pattern_combinations = {
            "32bit": [],
            "64bit": []
        }

        # Load behavior patterns from all modules
        for module in self.loader.get_pattern_modules():
            self._load_module_patterns(module)

        # Build the decision tree after loading all patterns
        self.decision_tree = build_pattern_decision_tree(self.pattern_combinations)

    def _load_module_patterns(self, module):
        """Load patterns from a single module into the combined collections"""
        # Skip loading architecture patterns since we import them directly
        # Only load behavior patterns
        if hasattr(module, "behavior_patterns"):
            for arch, categories in module.behavior_patterns.items():
                for category, patterns in categories.items():
                    if category not in self.behavior_patterns[arch]:
                        self.behavior_patterns[arch][category] = []
                    self.behavior_patterns[arch][category].extend(patterns)

        # Load pattern combinations
        if hasattr(module, "pattern_combinations"):
            for arch, combinations in module.pattern_combinations.items():
                self.pattern_combinations[arch].extend(combinations)

    def determine_architecture(self, data):
        """
        Determine if code is 32-bit or 64-bit.
        Returns: "32bit", "64bit", or None if undetermined
        """
        # Count matches for each architecture
        count_32bit = 0
        count_64bit = 0

        for pattern in self.architecture_patterns["32bit"]:
            matches = find_all_patterns(data, pattern)
            count_32bit += len(matches)

        for pattern in self.architecture_patterns["64bit"]:
            matches = find_all_patterns(data, pattern)
            count_64bit += len(matches)

        # Decide based on count
        if count_32bit > 0 and count_64bit == 0:
            return "32bit"
        elif count_64bit > 0 and count_32bit == 0:
            return "64bit"
        elif count_64bit > count_32bit:
            return "64bit"
        elif count_32bit > count_64bit:
            return "32bit"
        elif count_32bit > 0:  # Equal counts but not zero
            return "mixed"
        else:
            return None

    def match_specific_shellcode(self, data, arch):
        """Check for exact matches of known shellcode patterns"""
        patterns = self.behavior_patterns.get(arch, {}).get("specific", [])
        if not patterns:
            return False

        for pattern in patterns:
            if find_pattern(data, pattern) != -1:
                return True
        return False

    def match_combined_shellcode(self, data, arch, max_distance=100):
        """
        Look for combinations of patterns that indicate shellcode using the decision tree.
        Returns True if patterns from multiple categories are found within max_distance.
        """
        # Use the decision tree to efficiently check for pattern combinations
        is_match, matched_categories = self.decision_tree.match_patterns(
            data, arch, self, max_distance)

        return is_match