import os
import importlib.util
import sys


class PatternLoader:
    def __init__(self, patterns_dir="patterns"):
        self.patterns_dir = patterns_dir
        self.pattern_modules = []

    def load_patterns(self):
        """Load all pattern modules from the patterns directory"""
        if not os.path.exists(self.patterns_dir):
            print(f"Warning: Patterns directory '{self.patterns_dir}' does not exist!")
            return

        # Get all python files in the patterns directory
        pattern_files = [f for f in os.listdir(self.patterns_dir)
                         if f.endswith('.py') and not f.startswith('__')]

        for file_name in pattern_files:
            module_name = file_name[:-3]  # Remove .py extension
            try:
                # Load the module
                module_path = os.path.join(self.patterns_dir, file_name)
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                if spec is None:
                    print(f"Warning: Could not load pattern file '{file_name}'")
                    continue

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                # Store the module
                self.pattern_modules.append(module)
                print(f"Loaded pattern module: {module_name}")
            except Exception as e:
                print(f"Error loading pattern file '{file_name}': {str(e)}")

    def get_pattern_modules(self):
        """Return all loaded pattern modules"""
        return self.pattern_modules