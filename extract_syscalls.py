import re
import sys

def extract_and_filter_syscall_names(file_content):
    syscalls = []
    in_syscall_list = False
    # Keywords to identify architecture-specific syscalls
    arch_keywords = [
        "x86", "sparc", "ARM", "Alpha", "PowerPC", "s390", "m68k", "IA-64",
        "Xtensa", "ARC", "RISC-V", "OpenRISC", "Blackfin", "Metag", "Tile",
        "AVR32", "mips", "OABI", "EABI", "only"
    ]

    for line in file_content.splitlines():
        if "System call                Kernel        Notes" in line:
            in_syscall_list = True
            continue
        if in_syscall_list and not line.strip():
            break
        if in_syscall_list:
            match = re.match(r"(\w+)\(2\)\s+.*?(?:\s{2,}(.*))?", line.strip())
            if match:
                syscall_name = match.group(1)
                notes = match.group(2) if match.group(2) else ""

                # Check if any architecture keyword is in the notes
                is_arch_specific = False
                for keyword in arch_keywords:
                    if keyword.lower() in notes.lower():
                        is_arch_specific = True
                        break

                if not is_arch_specific:
                    syscalls.append(syscall_name)
    return syscalls

# Read content from stdin
content = sys.stdin.read()

syscall_names = extract_and_filter_syscall_names(content)
output_file_path = r"C:\Users\cba72\OneDrive\바탕 화면\2025-1\generate_bpf\syscall_names.txt"
with open(output_file_path, "w", encoding="utf-8") as f:
    for name in syscall_names:
        f.write(name + "\n")

print(f"Extracted {len(syscall_names)} filtered syscall names to {output_file_path}")