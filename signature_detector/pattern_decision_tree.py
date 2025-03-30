from pattern_utils import find_pattern


class PatternNode:
    def __init__(self, category=None, is_terminal=False, combo_name=None, required_categories=None):
        self.category = category
        self.children = []
        self.is_terminal = is_terminal
        self.combo_name = combo_name
        self.required_categories = required_categories or []

    def add_child(self, node):
        """Add a child node to this node"""
        self.children.append(node)
        return node


class PatternDecisionTree:
    def __init__(self):
        self.root = PatternNode()
        self.architectures = {}

    def build_trees(self, pattern_combinations):
        """
        Build a decision tree for each architecture based on pattern combinations
        pattern_combinations: dict mapping architecture to list of category combinations
        """
        for arch, combinations in pattern_combinations.items():

            arch_root = PatternNode()
            self.architectures[arch] = arch_root


            for i, combination in enumerate(combinations):
                current_node = arch_root


                combo_name = None
                if isinstance(combination, dict):
                    combo_name = combination.get('name', f'combination_{i}')
                    categories = combination.get('required_categories', [])
                else:
                    categories = combination
                    combo_name = f'combination_{i}'

                for i, category in enumerate(categories):
                    found = False
                    for child in current_node.children:
                        if child.category == category:
                            current_node = child
                            found = True
                            break

                    if not found:
                        is_terminal = (i == len(categories) - 1)
                        new_node = PatternNode(
                            category,
                            is_terminal,
                            combo_name if is_terminal else None,
                            categories  # Store all required categories
                        )
                        current_node.add_child(new_node)
                        current_node = new_node

                    if i == len(categories) - 1:
                        current_node.is_terminal = True
                        current_node.combo_name = combo_name
                        current_node.required_categories = categories

    def match_patterns(self, data, arch, pattern_manager, max_distance=100, return_names=False):
        """
        Use the decision tree to efficiently check if data matches any pattern combination
        for the given architecture.

        Returns: (is_match, matched_categories, matched_combo_names) if return_names=True
                 (is_match, matched_categories, []) if return_names=False
        """
        if arch not in self.architectures:
            return False, [], []

        all_matched_categories = set()

        for category, patterns in pattern_manager.behavior_patterns.get(arch, {}).items():
            for pattern in patterns:
                if find_pattern(data, pattern) != -1:
                    all_matched_categories.add(category)
                    break

        matched_combinations = []
        for combo in pattern_manager.pattern_combinations.get(arch, []):
            if isinstance(combo, dict):
                combo_name = combo.get('name')
                required_categories = set(combo.get('required_categories', []))
            else:
                combo_name = '+'.join(combo)
                required_categories = set(combo)

            if required_categories and required_categories.issubset(all_matched_categories):
                matched_combinations.append(combo_name)
                print(f"DEBUG: Matched combination {combo_name}")

        is_match = len(matched_combinations) > 0
        return is_match, list(all_matched_categories), matched_combinations if return_names else []

    def _dfs_match(self, node, data, matched_categories, matched_names, pattern_manager, arch, max_distance):
        """
        Depth-first search through the decision tree to find a matching pattern combination
        Legacy method - kept for backward compatibility
        """
        if node.is_terminal and len(matched_categories) > 0:
            # verify that all required categories were matched
            all_required_matched = True
            for required_cat in node.required_categories:
                if required_cat not in matched_categories:
                    all_required_matched = False
                    print(f"DEBUG: Missing required category {required_cat} for {node.combo_name}")
                    break

            if all_required_matched:
                if node.combo_name and node.combo_name not in matched_names:
                    matched_names.append(node.combo_name)
                    print(f"DEBUG: Found complete match for {node.combo_name}")
                return True, matched_categories, matched_names
            else:
                return False, matched_categories, matched_names

        if node.category is None:
            final_match = False
            final_categories = []
            final_names = []

            for child in node.children:
                is_match, categories, names = self._dfs_match(
                    child, data, matched_categories.copy(), matched_names.copy(),
                    pattern_manager, arch, max_distance)

                if is_match:
                    final_match = True
                    final_categories.extend([c for c in categories if c not in final_categories])
                    final_names.extend([n for n in names if n not in final_names])

            return final_match, final_categories, final_names

        category = node.category
        behavior_patterns = pattern_manager.behavior_patterns.get(arch, {}).get(category, [])

        category_matched = False

        for pattern in behavior_patterns:
            pos = find_pattern(data, pattern)
            if pos != -1:
                category_matched = True
                print(f"DEBUG: Matched category {category} at position {pos}")
                break

        if not category_matched:
            return False, [], []

        updated_matches = matched_categories + [category]

        if node.is_terminal:
            # all required categories must be matched
            all_required_matched = True
            for required_cat in node.required_categories:
                if required_cat not in updated_matches:
                    all_required_matched = False
                    print(f"DEBUG: Missing required category {required_cat} for {node.combo_name}")
                    break

            if all_required_matched:
                updated_names = matched_names.copy()
                if node.combo_name and node.combo_name not in updated_names:
                    updated_names.append(node.combo_name)
                    print(f"DEBUG: Terminal node complete match: {node.combo_name}")
                return True, updated_matches, updated_names
            else:
                return False, updated_matches, matched_names

        for child in node.children:
            is_match, categories, names = self._dfs_match(
                child, data, updated_matches, matched_names.copy(),
                pattern_manager, arch, max_distance)

            if is_match:
                return True, categories, names

        return False, [], []

def build_pattern_decision_tree(pattern_combinations):
    """
    Build and return a pattern decision tree from the given pattern combinations
    """
    tree = PatternDecisionTree()
    tree.build_trees(pattern_combinations)
    return tree