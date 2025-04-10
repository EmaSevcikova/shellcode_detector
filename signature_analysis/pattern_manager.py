from pattern_utils import *
from pattern_loader import PatternLoader
from patterns.arch_patterns import architecture_patterns
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

        # Add mapping to track which categories belong to which module
        self.category_to_module = {
            "32bit": {},
            "64bit": {}
        }

        # Load behavior patterns from all modules
        for module in self.loader.get_pattern_modules():
            self._load_module_patterns(module)

        # Build the decision tree after loading all patterns
        self.decision_tree = build_pattern_decision_tree(self.pattern_combinations)

        # Store the pattern names
        self.pattern_names = self.loader.get_pattern_names()

    def _load_module_patterns(self, module):
        """Load patterns from a single module into the combined collections"""
        module_name = module.__name__

        # Only load behavior patterns
        if hasattr(module, "behavior_patterns"):
            for arch, categories in module.behavior_patterns.items():
                for category, patterns in categories.items():
                    if category not in self.behavior_patterns[arch]:
                        self.behavior_patterns[arch][category] = []
                    self.behavior_patterns[arch][category].extend(patterns)

                    # Track which module this category comes from
                    self.category_to_module[arch][category] = module_name

        # Load pattern combinations
        if hasattr(module, "pattern_combinations"):
            for arch, combinations in module.pattern_combinations.items():
                self.pattern_combinations[arch].extend(combinations)

    def get_pattern_name_for_category(self, arch, category):
        """Get the pattern name for a specific category"""
        module_name = self.category_to_module.get(arch, {}).get(category)
        if module_name:
            return self.pattern_names.get(module_name, module_name)
        return None

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

    def match_combined_shellcode(self, data, arch, max_distance=100, return_names=False):
        """
        Look for combinations of patterns that indicate shellcode using the decision tree.

        Args:
            data: Binary data to analyze
            arch: Architecture to check
            max_distance: Maximum distance between related patterns
            return_names: Whether to return the names of matched combinations

        Returns:
            If return_names is False: bool indicating if a combination was matched
            If return_names is True: tuple (is_matched, list_of_combination_names, list_of_pattern_names)
        """
        # Use the decision tree to efficiently check for pattern combinations
        is_match, matched_categories, matched_combo_names, matched_pattern_names = self.decision_tree.match_patterns(
            data, arch, self, max_distance, return_names)

        if return_names:
            return is_match, matched_combo_names, matched_pattern_names
        else:
            return is_match