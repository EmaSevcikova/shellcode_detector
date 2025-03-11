# pattern_utils.py
def find_pattern(buffer, pattern, max_iter=0):
    """Find the first occurrence of a pattern in a buffer."""
    pattern_length = len(pattern)
    buffer_length = len(buffer)
    for i in range(buffer_length - pattern_length + 1):
        if max_iter != 0 and i > max_iter:
            break
        match = True
        for j in range(pattern_length):
            # Handle wildcards (represented as None or values > 0xF0 which aren't valid x86 opcodes)
            if pattern[j] is None or (isinstance(pattern[j], int) and pattern[j] > 0xF0):
                continue
            if buffer[i + j] != pattern[j]:
                match = False
                break
        if match:
            return i
    return -1


def find_all_patterns(buffer, pattern, max_iter=0):
    """Find all occurrences of a pattern in a buffer."""
    results = []
    pattern_length = len(pattern)
    buffer_length = len(buffer)
    for i in range(buffer_length - pattern_length + 1):
        if max_iter != 0 and i > max_iter:
            break
        match = True
        for j in range(pattern_length):
            # Handle wildcards
            if pattern[j] is None or (isinstance(pattern[j], int) and pattern[j] > 0xF0):
                continue
            if buffer[i + j] != pattern[j]:
                match = False
                break
        if match:
            results.append(i)
    return results


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
        locations = find_all_patterns(buffer, pattern)
        first_pattern_locs.extend(locations)

    if not first_pattern_locs:
        return False

    # For each starting point, try to find all other patterns within max_distance
    for start_loc in first_pattern_locs:
        all_patterns_found = True

        # Check if all remaining pattern sets can be found
        for pattern_set in pattern_sets[1:]:
            pattern_set_found = False

            for pattern in pattern_set:
                # Look for this pattern within the specified distance
                search_start = max(0, start_loc - max_distance)
                search_end = min(len(buffer), start_loc + max_distance)
                search_buffer = buffer[search_start:search_end]

                if find_pattern(search_buffer, pattern) != -1:
                    pattern_set_found = True
                    break

            if not pattern_set_found:
                all_patterns_found = False
                break

        if all_patterns_found:
            return True

    return False
