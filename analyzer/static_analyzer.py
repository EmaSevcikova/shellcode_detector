import yara


def load_rules(rule_file):
    return yara.compile(filepaths={'shellcode': rule_file})


def scan_memory(memory_dump, rules):
    matches = rules.match(data=memory_dump)
    return [str(m) for m in matches]
