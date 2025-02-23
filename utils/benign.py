from pwn import *
import os

# Start the Hello World program
p = process("./hello")

# Read and print the PID
pid = p.pid
print(f"Process PID: {pid}")

# Attach GDB and set a breakpoint
gdb.attach(p, """
break main
continue
""")

# Wait to ensure execution reaches the breakpoint
p.wait_for_close()

# Generate a memory dump using gcore
os.system(f"gcore -o hello_dump {pid}")

print("Memory dump saved as hello_dump.*")
