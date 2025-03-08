from patterns import prolog32_patterns, prolog64_patterns
from pattern_utils import find_pattern

class PatternManager:
    def __init__(self):
        self.patterns = {
            "32bit": prolog32_patterns,
            "64bit": prolog64_patterns
        }

    def is_32bit_code(self, data):
        for pattern in self.patterns["32bit"]:
            if find_pattern(data, pattern) != -1:
                return True
        return False

    def is_64bit_code(self, data):
        for pattern in self.patterns["64bit"]:
            if find_pattern(data, pattern) != -1:
                return True
        return False