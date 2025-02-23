import struct


def extract_executable_memory(core_dump_path, output_bin_path):
    with open(core_dump_path, "rb") as f:
        data = f.read()

    elf_header = data[:64]  # ELF header (first 64 bytes)

    # Verify ELF magic number
    if not elf_header.startswith(b"\x7fELF"):
        print("[!] Not a valid ELF file.")
        return

    # Extract ELF class (32-bit or 64-bit)
    elf_class = elf_header[4]
    is_64bit = elf_class == 2

    # Extract program header table info
    if is_64bit:
        e_phoff = struct.unpack("<Q", elf_header[32:40])[0]  # Offset of program header table
        e_phentsize = struct.unpack("<H", elf_header[54:56])[0]  # Entry size
        e_phnum = struct.unpack("<H", elf_header[56:58])[0]  # Number of entries
    else:
        e_phoff = struct.unpack("<I", elf_header[28:32])[0]
        e_phentsize = struct.unpack("<H", elf_header[42:44])[0]
        e_phnum = struct.unpack("<H", elf_header[44:46])[0]

    executable_sections = []

    for i in range(e_phnum):
        ph_offset = e_phoff + (i * e_phentsize)
        if is_64bit:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
                "<IIQQQQQQ", data[ph_offset: ph_offset + 56]
            )
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                "<IIIIIIII", data[ph_offset: ph_offset + 32]
            )

        # Check if this segment is executable (PF_X flag = 0x1)
        if p_flags & 1:
            print(f"[*] Found executable segment at 0x{p_vaddr:x} (size: {p_filesz} bytes)")
            executable_sections.append((p_offset, p_filesz))

    # Extract and save the executable regions
    if not executable_sections:
        print("[!] No executable sections found.")
        return

    with open(output_bin_path, "wb") as out_file:
        for offset, size in executable_sections:
            out_file.write(data[offset: offset + size])

    print(f"[+] Extracted executable memory saved to: {output_bin_path}")

