from pattern_utils import find_pattern

class PatternNode:
    def __init__(self, category=None, is_terminal=False):
        self.category = category  # Pattern category to match
        self.children = []  # Child nodes
        self.is_terminal = is_terminal  # True if this node represents a complete pattern combination

    def add_child(self, node):
        """Add a child node to this node"""
        self.children.append(node)
        return node


class PatternDecisionTree:
    def __init__(self):
        self.root = PatternNode()  # Root node doesn't represent any category
        self.architectures = {}  # Map of architecture to its decision tree root

    def build_trees(self, pattern_combinations):
        """
        Build a decision tree for each architecture based on pattern combinations
        pattern_combinations: dict mapping architecture to list of category combinations
        """
        for arch, combinations in pattern_combinations.items():
            # Create a root node for this architecture
            arch_root = PatternNode()
            self.architectures[arch] = arch_root

            # Add each combination as a path in the tree
            for combination in combinations:
                current_node = arch_root

                # Add nodes for each category in the combination
                for i, category in enumerate(combination):
                    # Check if this category already exists as a child
                    found = False
                    for child in current_node.children:
                        if child.category == category:
                            current_node = child
                            found = True
                            break

                    if not found:
                        # Create a new node for this category
                        is_terminal = (i == len(combination) - 1)
                        new_node = PatternNode(category, is_terminal)
                        current_node.add_child(new_node)
                        current_node = new_node

                    # Make the last node in the path a terminal node
                    if i == len(combination) - 1:
                        current_node.is_terminal = True

    def match_patterns(self, data, arch, pattern_manager, max_distance=100):
        """
        Use the decision tree to efficiently check if data matches any pattern combination
        for the given architecture.

        Returns: (is_match, matched_categories)
        """
        if arch not in self.architectures:
            return False, []

        # Get the root node for this architecture
        root = self.architectures[arch]

        # Start DFS from the root node
        return self._dfs_match(root, data, [], pattern_manager, arch, max_distance)

    def _dfs_match(self, node, data, matched_categories, pattern_manager, arch, max_distance):
        """
        Depth-first search through the decision tree to find a matching pattern combination
        """
        # If this is a terminal node and we've matched all categories, we have a match
        if node.is_terminal and len(matched_categories) > 0:
            return True, matched_categories

        # If this is the root node, check all children
        if node.category is None:
            for child in node.children:
                is_match, categories = self._dfs_match(child, data, matched_categories.copy(),
                                                       pattern_manager, arch, max_distance)
                if is_match:
                    return True, categories
            return False, []

        # Otherwise, check if we can match this node's category
        category = node.category
        behavior_patterns = pattern_manager.behavior_patterns.get(arch, {}).get(category, [])

        # Check if any pattern in this category matches the data
        category_matched = False
        for pattern in behavior_patterns:
            if find_pattern(data, pattern) != -1:
                category_matched = True
                break

        if not category_matched:
            return False, []

        # Add this category to the matched categories
        updated_matches = matched_categories + [category]

        # If this is a terminal node, we have a match
        if node.is_terminal:
            return True, updated_matches

        # Otherwise, check if any child node matches
        for child in node.children:
            # For efficiency, we need to check if the patterns are within max_distance
            # This is a simplification - a full implementation would check the exact distances
            # between pattern matches
            is_match, categories = self._dfs_match(child, data, updated_matches,
                                                   pattern_manager, arch, max_distance)
            if is_match:
                return True, categories

        return False, []


# Helper function to create a decision tree from pattern combinations
def build_pattern_decision_tree(pattern_combinations):
    """
    Build and return a pattern decision tree from the given pattern combinations
    """
    tree = PatternDecisionTree()
    tree.build_trees(pattern_combinations)
    return tree
