def find_pattern(buffer, pattern, max_iter=0):
    pattern_length = len(pattern)
    buffer_length = len(buffer)
    for i in range(buffer_length - pattern_length + 1):
        if max_iter != 0 and i > max_iter:
            break
        if buffer[i:i + pattern_length] == pattern:
            return i
    return -1