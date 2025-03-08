class ShellcodeDetector:
    def __init__(self, pattern_manager):
        self.pattern_manager = pattern_manager

    def detect_shellcode(self, data):
        if self.pattern_manager.is_32bit_code(data):
            print("32-bit shellcode detected.")
            return True
        elif self.pattern_manager.is_64bit_code(data):
            print("64-bit shellcode detected.")
            return True
        return False