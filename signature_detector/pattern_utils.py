# pattern_utils.py
def find_pattern(buffer, pattern, max_iter=0):
    """Find the first occurrence of a pattern in a buffer."""
    pattern_length = len(pattern)
    buffer_length = len(buffer)
    max_index = min(buffer_length - pattern_length + 1, max_iter if max_iter > 0 else buffer_length)

    for i in range(max_index):
        if all(
                pattern[j] is None or
                (isinstance(pattern[j], int) and pattern[j] > 0xF0) or
                buffer[i + j] == pattern[j]
                for j in range(pattern_length)
        ):
            return i
    return -1


def find_all_patterns(buffer, pattern, max_iter=0):
    """Find all occurrences of a pattern in a buffer."""
    pattern_length = len(pattern)
    buffer_length = len(buffer)
    max_index = min(buffer_length - pattern_length + 1, max_iter if max_iter > 0 else buffer_length)

    return [
        i for i in range(max_index)
        if all(
            pattern[j] is None or
            (isinstance(pattern[j], int) and pattern[j] > 0xF0) or
            buffer[i + j] == pattern[j]
            for j in range(pattern_length)
        )
    ]


def find_pattern_sets(buffer, pattern_sets, max_distance=100):
    """
    Find occurrences of multiple pattern sets with distance constraints.
    Returns True if all pattern sets are found within max_distance of each other.
    """
    if not pattern_sets:
        return False

    # Find locations of first pattern set
    first_pattern_locs = []
    for pattern in pattern_sets[0]:
        first_pattern_locs.extend(find_all_patterns(buffer, pattern))

    if not first_pattern_locs:
        return False

    # For each starting point, check if all other patterns exist within max_distance
    for start_loc in first_pattern_locs:
        search_start = max(0, start_loc - max_distance)
        search_end = min(len(buffer), start_loc + max_distance)
        search_buffer = buffer[search_start:search_end]

        # Check if all remaining pattern sets can be found in the search buffer
        if all(
                any(
                    find_pattern(search_buffer, pattern) != -1
                    for pattern in pattern_set
                )
                for pattern_set in pattern_sets[1:]
        ):
            return True

    return False