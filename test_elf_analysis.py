#!/usr/bin/env python3
"""Test ELF analysis only (no device connection required)"""

import subprocess
import os

def analyze_elf_sections():
    """Analyze actual ELF file sections using arm-zephyr-eabi-objdump"""
    elf_file = "build/zephyr/zephyr.elf"
    objdump_path = "/Users/user/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-objdump"
    nm_path = "/Users/user/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-nm"
    
    if not os.path.exists(elf_file):
        print(f"❌ ELF file not found: {elf_file}")
        return None
    
    print(f"✓ Found ELF file: {elf_file}")
    
    try:
        # Get section information using -S (size) flag
        print("\n=== SECTIONS (using arm-zephyr-eabi-readelf) ===")
        # Try readelf first for more reliable size information
        readelf_path = "/Users/user/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-readelf"
        result = subprocess.run(
            [readelf_path, "-S", elf_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        sections = {}
        for line in result.stdout.split('\n'):
            if '[' in line and ']' in line:  # Section header line
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        name = parts[1]
                        size_hex = parts[5]
                        size = int(size_hex, 16)
                        if size > 0:
                            sections[name] = size
                            print(f"  {name:<15} {size:>8,} bytes ({size/1024:>6.1f} KB)")
                    except (ValueError, IndexError):
                        pass
        
        # Get symbol sizes
        print("\n=== TOP 20 LARGEST SYMBOLS ===")
        result = subprocess.run(
            [nm_path, "-S", elf_file],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        symbols = {}
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    size = int(parts[1], 16)
                    if size > 0:
                        name = parts[-1]
                        symbols[name] = size
                except (ValueError, IndexError):
                    pass
        
        sorted_symbols = sorted(symbols.items(), key=lambda x: x[1], reverse=True)[:20]
        for i, (name, size) in enumerate(sorted_symbols, 1):
            name_clean = name if len(name) <= 40 else name[:37] + "..."
            print(f"  {i:2d}. {name_clean:<40} {size:>8,} bytes ({size/1024:>6.1f} KB)")
        
        return {'sections': sections, 'symbols': symbols}
        
    except FileNotFoundError:
        print("❌ arm-zephyr-eabi-objdump or arm-zephyr-eabi-nm not found in PATH")
        return None
    except Exception as e:
        print(f"❌ Error analyzing ELF: {e}")
        return None

if __name__ == "__main__":
    elf_analysis = analyze_elf_sections()
    if elf_analysis:
        print("\n✅ ELF analysis successful!")
    else:
        print("\n❌ ELF analysis failed")
