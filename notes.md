## shellcode analyzer notes

# 1. setup
* simple **C** program with a known vulnerability (`vulnerable.c`)
* compilation with protection disabled
(e.g. `gcc -m32 -fno-stack-protector -z execstack -no-pie vulnerable.c -o vulnerable`)

# 2. test data
* list of test shellcodes
  * converted to shellcode binaries
  * sources: [shellcode api](https://shell-storm.org/shellcode/index.html), [exploit db](https://www.exploit-db.com/search?type=shellcode&platform=linux)
  * standardized shellcodes: `msfvenom`
  * optional: obfuscated payloads (XOR-encoded shellcode)
```
test_data/
├── shellcodes/           # Raw shellcode binaries
├── vulnerable_programs/  # Compiled vulnerable binaries
├── benign_programs/      # Benign binaries
└── memory_dumps/         # Pre-captured snapshots
    ├── malicious/
    └── benign/
```

# 3. exploitation simulation
* using `gdb`
	* starts the vulnerable process
	* inject payload and pause execution
	* capture memory dump using `gcore`

# 4. static analysis
* detect shellcode in the snapshot using `YARA` rules
	* non-executable regions marked as executable (e.g., heap/stack with `rwx` permissions)
	* long sequences of non-ASCII bytes
    * e.g. [shellcode rules](https://github.com/thewhiteninja/yarasploit/tree/master/linux)

# 5. dynamic analysis (instruction emulator)
* execution emulator (`Capstone` disassembler, `Unicorn` emulator)
	* extract code from VM snapshots (e.g., `.text` sections or executable regions)
	* emulate execution
	* shellcode behaviors:
        * track execution depth to avoid infinite loops 
        * hooks `system calls` (via `UC_HOOK_INTR`) to detect `execve`, `mprotect`, etc.
        * check stack/heap execution (`eip` in non-text regions)
        * indirect control flow (e.g., `jmp [eax]` where `eax` points to stack)
# 6. contextual correlation
* registers/CPU state:
  * `EIP`/`RIP` points to non-executable memory (e.g., stack/heap)
  * `ESP`/`RSP` for signs of buffer overflow (e.g., large offsets)
  * protocol analyzer??

# 7. expected workflow
```
[Vulnerable Process] → [Inject Shellcode Payload] → [Pause & Snapshot] → [Analyzer] → [Detect Shellcode]
                         ↑                                ↑
                      Exploit Script                  gcore/YARA/Unicorn
```

