#!/usr/bin/env python3
"""Simple test to collect benchmark metrics after inference"""

import sys
import struct
import subprocess
import os
from datetime import datetime
sys.path.insert(0, 'tools')
import mac_provider

def analyze_elf_sections():
    """Analyze actual ELF file sections using arm-zephyr-eabi-readelf"""
    elf_file = "build/zephyr/zephyr.elf"
    readelf_path = "/Users/user/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-readelf"
    nm_path = "/Users/user/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin/arm-zephyr-eabi-nm"
    
    if not os.path.exists(elf_file):
        return None
    
    try:
        # Get section information using readelf
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
                    except (ValueError, IndexError):
                        pass
        
        # Get symbol sizes
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
        
        return {'sections': sections, 'symbols': symbols}
    except Exception as e:
        return None

# Open output file
output_file = open('benchmark_results.txt', 'w')

def log(msg=''):
    """Log to both console and file"""
    print(msg)
    output_file.write(msg + '\n')
    output_file.flush()

# Connect to device
device = mac_provider.STM32Device('/dev/cu.usbmodem1203', 115200)
if not device.connect():
    log('✗ Failed to connect to device')
    output_file.close()
    sys.exit(1)

provider = mac_provider.ModelProvider()
model_pub = bytes([0xC0 + i for i in range(32)])
model_secret = bytes([0xE0 + i for i in range(32)])
code_hash = bytes([0x01 + i for i in range(32)])
model_id = 0x00000001

log('\n' + '='*70)
log('BENCHMARK COLLECTION TEST - DEVICE TO SECURE ENCLAVE')
log('='*70)
log(f'Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
log(f'Device: STM32L552ZE-Q (Cortex-M33 @ 110 MHz)')
log(f'Port: /dev/cu.usbmodem1203')
log('='*70)

# Step 1: ECDH
log('\n[1] ECDH Handshake...')
if not mac_provider.perform_ecdh_handshake(device):
    log('✗ Failed')
    device.disconnect()
    output_file.close()
    sys.exit(1)
log('✓ Done')

# Step 2: Get EnclaveInfo
log('[2] Getting EnclaveInfo...')
data = model_pub + model_secret + code_hash + struct.pack('<I', model_id)
if not device.send_command(mac_provider.CMD_COMPUTE_ENCLAVE_INFO, data):
    log('✗ Failed')
    device.disconnect()
    output_file.close()
    sys.exit(1)
resp = device.read_response()
if not resp or resp[0] != 0x00:
    log('✗ Failed')
    device.disconnect()
    output_file.close()
    sys.exit(1)
enclave_info = resp[1]
log(f'  EnclaveInfo: {enclave_info.hex()} (32 bytes)')
log('✓ Done')

# Step 3: M_update
log('[3] Sending M_update (quota=10)...')
nonce, ciphertext, tag = provider.generate_m_update(10, enclave_info)
m_update_data = nonce + ciphertext + tag
if not device.send_command(mac_provider.CMD_VALIDATE_M_UPDATE, m_update_data):
    log('✗ Failed')
    device.disconnect()
    output_file.close()
    sys.exit(1)
resp = device.read_response()
if not resp or resp[0] != 0x00:
    log('✗ Failed')
    device.disconnect()
    output_file.close()
    sys.exit(1)
log(f'  Nonce: {nonce.hex()} (12 bytes)')
log(f'  Ciphertext size: {len(ciphertext)} bytes')
log(f'  Auth tag: {tag.hex()} (16 bytes)')
log('✓ Done')

# Step 4: Run inference
log('[4] Running inference...')
if not device.send_command(mac_provider.CMD_RUN_INFERENCE):
    log('✗ Failed')
    device.disconnect()
    output_file.close()
    sys.exit(1)
resp = device.read_response()
if not resp or resp[0] != 0x00:
    log('✗ Failed')
    device.disconnect()
    output_file.close()
    sys.exit(1)
log('✓ Done')

# Step 5: Get NS benchmark metrics
log('\n[5] Retrieving NS benchmark metrics...')
if not device.send_command(0x08):  # CMD_GET_BENCHMARK
    log('✗ Failed to send')
    device.disconnect()
    output_file.close()
    sys.exit(1)

resp = device.read_response()
if not resp or resp[0] != 0x00:
    log(f'✗ Failed (status {resp[0] if resp else "None"})')
    device.disconnect()
    output_file.close()
    sys.exit(1)

ns_data = resp[1]
log(f'✓ Received {len(ns_data)} bytes')

# Step 6: Get Secure benchmark metrics
log('[6] Retrieving Secure benchmark metrics...')
if not device.send_command(0x09):  # CMD_GET_BENCHMARK (Secure via PSA)
    log('✗ Failed to send')
    device.disconnect()
    output_file.close()
    sys.exit(1)

resp = device.read_response()
if not resp or resp[0] != 0x00:
    log(f'✗ Failed (status {resp[0] if resp else "None"})')
    device.disconnect()
    output_file.close()
    sys.exit(1)

s_data = resp[1]
log(f'✓ Received {len(s_data)} bytes')

# Parse NS metrics
if len(ns_data) >= 72:
    # Parse benchmark_metrics_t (18 x uint32_t = 72 bytes)
    ns_values = struct.unpack('<18I', ns_data[:72])
    
    log('\n' + '='*70)
    log('NON-SECURE (NS) BENCHMARK RESULTS')
    log('='*70)
    
    log(f'\nEnclave Lifecycle:')
    log(f'  Create:  {ns_values[0]:>10,} cycles ({ns_values[0]/110000:.1f} ms)')
    log(f'  Destroy: {ns_values[1]:>10,} cycles ({ns_values[1]/110000:.1f} ms)')
    
    log(f'\nCryptographic Operations:')
    log(f'  AES Decrypt:    {ns_values[2]:>10,} cycles ({ns_values[2]/110000:.1f} ms)')
    log(f'  Late Hash:      {ns_values[3]:>10,} cycles ({ns_values[3]/110000:.1f} ms)')
    log(f'  Inference Hash: {ns_values[4]:>10,} cycles ({ns_values[4]/110000:.1f} ms)')
    
    log(f'\nInference Performance:')
    log(f'  Early Layers: {ns_values[5]:>10,} cycles ({ns_values[5]/110000:.1f} ms)')
    log(f'  Late Layers:  {ns_values[6]:>10,} cycles ({ns_values[6]/110000:.1f} ms)')
    log(f'  Total:        {ns_values[7]:>10,} cycles ({ns_values[7]/110000:.1f} ms)')
    
    log(f'\nEnd-to-End:')
    log(f'  run_enclave(): {ns_values[8]:>10,} cycles ({ns_values[8]/110000:.1f} ms)')
    
    log(f'\nNS Memory Usage:')
    log(f'  Heap Used:  {ns_values[9]:>10,} bytes ({ns_values[9]/1024:.1f} KB)')
    log(f'  Heap Free:  {ns_values[10]:>10,} bytes ({ns_values[10]/1024:.1f} KB)')
    log(f'  Stack Used: {ns_values[11]:>10,} bytes ({ns_values[11]/1024:.1f} KB)')
    
    if ns_values[13] > 0:
        log(f'  RAM Used:   {ns_values[12]:>10,} / {ns_values[13]:,} bytes ({ns_values[12]/ns_values[13]*100:.1f}%)')
    else:
        log(f'  RAM Used:   {ns_values[12]:>10,} / {ns_values[13]:,} bytes (N/A)')
    
    if ns_values[15] > 0:
        log(f'  Flash Used: {ns_values[14]:>10,} / {ns_values[15]:,} bytes ({ns_values[14]/ns_values[15]*100:.1f}%)')
    else:
        log(f'  Flash Used: {ns_values[14]:>10,} / {ns_values[15]:,} bytes (N/A)')
    
    log(f'\nCounters:')
    log(f'  Inferences:   {ns_values[16]}')
    log(f'  Recreations:  {ns_values[17]}')
else:
    log(f'✗ NS data too short: {len(ns_data)} bytes (expected >= 72)')

# Parse Secure metrics
if len(s_data) >= 80:
    # Parse secure_benchmark_metrics_t
    # 3 x uint64_t (crypto ops) + 4 x uint64_t (counter mgmt) + 4 x uint32_t (counts) + 4 x uint32_t (memory)
    # = 7*8 + 8*4 = 56 + 32 = 88 bytes
    s_crypto = struct.unpack('<3Q', s_data[0:24])  # 3 uint64_t
    s_counter = struct.unpack('<4Q', s_data[24:56])  # 4 uint64_t
    s_counts = struct.unpack('<4I', s_data[56:72])  # 4 uint32_t
    s_memory = struct.unpack('<4I', s_data[72:88])  # 4 uint32_t
    
    log('\n' + '='*70)
    log('SECURE (S) BENCHMARK RESULTS')
    log('='*70)
    
    log(f'\nCryptographic Operations (Secure):')
    log(f'  AES Decrypt:    {s_crypto[0]:>10,} cycles ({s_crypto[0]/110000:.1f} ms) [{s_counts[0]} ops]')
    log(f'  Late Hash:      {s_crypto[1]:>10,} cycles ({s_crypto[1]/110000:.1f} ms) [{s_counts[1]} ops]')
    log(f'  Digest Compute: {s_crypto[2]:>10,} cycles ({s_crypto[2]/110000:.1f} ms) [{s_counts[2]} ops]')
    
    log(f'\nCounter Management (Secure):')
    log(f'  Get Max:        {s_counter[0]:>10,} cycles ({s_counter[0]/110000:.1f} ms)')
    log(f'  Check Allowed:  {s_counter[1]:>10,} cycles ({s_counter[1]/110000:.1f} ms)')
    log(f'  Increment:      {s_counter[2]:>10,} cycles ({s_counter[2]/110000:.1f} ms)')
    log(f'  Reset:          {s_counter[3]:>10,} cycles ({s_counter[3]/110000:.1f} ms)')
    log(f'  Total Ops:      {s_counts[3]}')
    
    log(f'\nSecure Memory Usage:')
    if s_memory[1] > 0:
        log(f'  RAM Used:   {s_memory[0]:>10,} / {s_memory[1]:,} bytes ({s_memory[0]/s_memory[1]*100:.1f}%)')
    else:
        log(f'  RAM Used:   {s_memory[0]:>10,} / {s_memory[1]:,} bytes (N/A)')
    
    if s_memory[3] > 0:
        log(f'  Flash Used: {s_memory[2]:>10,} / {s_memory[3]:,} bytes ({s_memory[2]/s_memory[3]*100:.1f}%)')
    else:
        log(f'  Flash Used: {s_memory[2]:>10,} / {s_memory[3]:,} bytes (N/A)')
    
    # Combined summary
    log('\n' + '='*70)
    log('COMBINED SYSTEM METRICS')
    log('='*70)
    total_ram = ns_values[13] + s_memory[1]
    total_ram_used = ns_values[12] + s_memory[0]
    total_flash = ns_values[15] + s_memory[3]
    total_flash_used = ns_values[14] + s_memory[2]
    
    if total_ram > 0:
        log(f'Total RAM:   {total_ram_used:>10,} / {total_ram:,} bytes ({total_ram_used/total_ram*100:.1f}%)')
    if total_flash > 0:
        log(f'Total Flash: {total_flash_used:>10,} / {total_flash:,} bytes ({total_flash_used/total_flash*100:.1f}%)')
    
    # Memory Footprint Breakdown - Analyze actual ELF
    log('\n' + '='*70)
    log('MEMORY FOOTPRINT ANALYSIS')
    log('='*70)
    
    elf_analysis = analyze_elf_sections()
    
    if elf_analysis:
        sections = elf_analysis['sections']
        symbols = elf_analysis['symbols']
        
        log('\nELF Section Analysis (ACTUAL from build):')
        log('═' * 70)
        
        # Calculate total and display sections
        text_size = sections.get('text', 0)
        data_size = sections.get('datas', 0)
        bss_size = sections.get('bss', 0)
        rodata_size = sections.get('rodata', 0)
        
        log(f'\nFlash (ROM) Sections:')
        log(f'├─ .text (Code):         {text_size:>10,} bytes ({text_size/1024:>6.1f} KB)')
        log(f'├─ .rodata (Constants):  {rodata_size:>10,} bytes ({rodata_size/1024:>6.1f} KB)')
        log(f'└─ Total Flash Used:     {text_size + rodata_size:>10,} bytes ({(text_size + rodata_size)/1024:>6.1f} KB)')
        
        log(f'\nRAM (SRAM) Sections:')
        log(f'├─ .data (Initialized):  {data_size:>10,} bytes ({data_size/1024:>6.1f} KB)')
        log(f'├─ .bss (Zero-init):     {bss_size:>10,} bytes ({bss_size/1024:>6.1f} KB)')
        log(f'└─ Total RAM Used:       {data_size + bss_size:>10,} bytes ({(data_size + bss_size)/1024:>6.1f} KB)')
        
        # Top symbols by size
        log(f'\nLargest Symbols (Top 20):')
        sorted_symbols = sorted(symbols.items(), key=lambda x: x[1], reverse=True)[:20]
        
        for i, (name, size) in enumerate(sorted_symbols, 1):
            # Clean up symbol names
            name_clean = name.replace('_ZN', '').replace('E', '').split('.')[-1][:40]
            log(f'{i:2d}. {name_clean:<40} {size:>8,} bytes ({size/1024:>6.1f} KB)')
    else:
        log('\nCould not analyze ELF file. Using static breakdown:')
        log('Run: west build to generate build/zephyr/zephyr.elf')
    
else:
    log(f'✗ Secure data too short: {len(s_data)} bytes (expected >= 88)')

log('\n' + '='*70)
log('Test completed successfully')
log('='*70)
log(f'Results saved to: benchmark_results.txt')

device.disconnect()
output_file.close()
