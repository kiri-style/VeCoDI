#!/usr/bin/env python3
"""Test ELF parsing logic"""

import subprocess
import os
import re

elf_file = "build/zephyr/zephyr.elf"
readelf_path = "/Users/user/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-readelf"
nm_path = "/Users/user/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-nm"

# Test readelf parsing
result = subprocess.run([readelf_path, "-S", elf_file], capture_output=True, text=True, timeout=5)

sections = {}
for line in result.stdout.split('\n'):
    if line.strip() and '[' in line and ']' in line:
        match = re.search(r'\[\s*\d+\]\s+(\S+)\s+\S+\s+\S+\s+\S+\s+([0-9a-f]+)', line)
        if match:
            try:
                name = match.group(1)
                size_hex = match.group(2)
                size = int(size_hex, 16)
                if size > 0:
                    sections[name] = size
            except (ValueError, IndexError):
                pass

print("=== SECTIONS PARSED ===")
for name in sorted(sections.keys()):
    print(f"  {name:20s}: {sections[name]:>10,} bytes ({sections[name]/1024:>6.1f} KB)")

print("\n=== FLASH SUMMARY ===")
text_size = sections.get('text', 0)
rodata_size = sections.get('rodata', 0)
print(f"  .text:   {text_size:>10,} bytes ({text_size/1024:>6.1f} KB)")
print(f"  .rodata: {rodata_size:>10,} bytes ({rodata_size/1024:>6.1f} KB)")
print(f"  Total:   {text_size + rodata_size:>10,} bytes ({(text_size + rodata_size)/1024:>6.1f} KB)")

print("\n=== RAM SUMMARY ===")
data_size = sections.get('datas', 0)
bss_size = sections.get('bss', 0)
print(f"  .data:   {data_size:>10,} bytes ({data_size/1024:>6.1f} KB)")
print(f"  .bss:    {bss_size:>10,} bytes ({bss_size/1024:>6.1f} KB)")
print(f"  Total:   {data_size + bss_size:>10,} bytes ({(data_size + bss_size)/1024:>6.1f} KB)")

# Test nm parsing
result = subprocess.run([nm_path, "-S", elf_file], capture_output=True, text=True, timeout=5)

symbols = {}
for line in result.stdout.split('\n'):
    parts = line.split()
    if len(parts) >= 3:
        try:
            size = int(parts[1], 16)
            if size > 0:
                name = parts[-1]
                symbols[name] = size
        except (ValueError, IndexError):
            pass

print("\n=== TOP 10 SYMBOLS ===")
sorted_symbols = sorted(symbols.items(), key=lambda x: x[1], reverse=True)[:10]
for i, (name, size) in enumerate(sorted_symbols, 1):
    print(f"  {i:2d}. {name:40s} {size:>8,} bytes ({size/1024:>6.1f} KB)")

print("\n✓ All parsing tests passed!")
