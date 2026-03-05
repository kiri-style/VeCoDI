#!/usr/bin/env python3
"""Simple test to collect benchmark metrics after inference"""

import sys
import struct
sys.path.insert(0, 'tools')
import mac_provider

# Connect to device
device = mac_provider.STM32Device('/dev/cu.usbmodem1203', 115200)
if not device.connect():
    sys.exit(1)

provider = mac_provider.ModelProvider()
model_pub = bytes([0xC0 + i for i in range(32)])
model_secret = bytes([0xE0 + i for i in range(32)])
code_hash = bytes([0x01 + i for i in range(32)])
model_id = 0x00000001

print('\nQuick Benchmark Collection Test')
print('='*60)

# Step 1: ECDH
print('\n[1] ECDH Handshake...')
if not mac_provider.perform_ecdh_handshake(device):
    print('✗ Failed')
    device.disconnect()
    sys.exit(1)
print('✓ Done')

# Step 2: Get EnclaveInfo
print('[2] Getting EnclaveInfo...')
data = model_pub + model_secret + code_hash + struct.pack('<I', model_id)
if not device.send_command(mac_provider.CMD_COMPUTE_ENCLAVE_INFO, data):
    print('✗ Failed')
    device.disconnect()
    sys.exit(1)
resp = device.read_response()
if not resp or resp[0] != 0x00:
    print('✗ Failed')
    device.disconnect()
    sys.exit(1)
enclave_info = resp[1]
print('✓ Done')

# Step 3: M_update
print('[3] Sending M_update (quota=10)...')
nonce, ciphertext, tag = provider.generate_m_update(10, enclave_info)
m_update_data = nonce + ciphertext + tag
if not device.send_command(mac_provider.CMD_VALIDATE_M_UPDATE, m_update_data):
    print('✗ Failed')
    device.disconnect()
    sys.exit(1)
resp = device.read_response()
if not resp or resp[0] != 0x00:
    print('✗ Failed')
    device.disconnect()
    sys.exit(1)
print('✓ Done')

# Step 4: Run inference
print('[4] Running inference...')
if not device.send_command(mac_provider.CMD_RUN_INFERENCE):
    print('✗ Failed')
    device.disconnect()
    sys.exit(1)
resp = device.read_response()
if not resp or resp[0] != 0x00:
    print('✗ Failed')
    device.disconnect()
    sys.exit(1)
print('✓ Done')

# Step 5: Get NS benchmark metrics
print('[5] Retrieving NS benchmark metrics...')
if not device.send_command(0x08):  # CMD_GET_BENCHMARK
    print('✗ Failed to send')
    device.disconnect()
    sys.exit(1)

resp = device.read_response()
if not resp or resp[0] != 0x00:
    print(f'✗ Failed (status {resp[0] if resp else "None"})')
    device.disconnect()
    sys.exit(1)

ns_data = resp[1]
print(f'✓ Received {len(ns_data)} bytes')

# Step 6: Get Secure benchmark metrics
print('[6] Retrieving Secure benchmark metrics...')
if not device.send_command(0x09):  # CMD_GET_BENCHMARK (Secure via PSA)
    print('✗ Failed to send')
    device.disconnect()
    sys.exit(1)

resp = device.read_response()
if not resp or resp[0] != 0x00:
    print(f'✗ Failed (status {resp[0] if resp else "None"})')
    device.disconnect()
    sys.exit(1)

s_data = resp[1]
print(f'✓ Received {len(s_data)} bytes')

# Parse NS metrics
if len(ns_data) >= 72:
    # Parse benchmark_metrics_t (18 x uint32_t = 72 bytes)
    ns_values = struct.unpack('<18I', ns_data[:72])
    
    print('\n' + '='*60)
    print('NON-SECURE (NS) BENCHMARK RESULTS')
    print('='*60)
    
    print(f'\nEnclave Lifecycle:')
    print(f'  Create:  {ns_values[0]:>10,} cycles ({ns_values[0]/110000:.1f} ms)')
    print(f'  Destroy: {ns_values[1]:>10,} cycles ({ns_values[1]/110000:.1f} ms)')
    
    print(f'\nCryptographic Operations:')
    print(f'  AES Decrypt:    {ns_values[2]:>10,} cycles ({ns_values[2]/110000:.1f} ms)')
    print(f'  Late Hash:      {ns_values[3]:>10,} cycles ({ns_values[3]/110000:.1f} ms)')
    print(f'  Inference Hash: {ns_values[4]:>10,} cycles ({ns_values[4]/110000:.1f} ms)')
    
    print(f'\nInference Performance:')
    print(f'  Early Layers: {ns_values[5]:>10,} cycles ({ns_values[5]/110000:.1f} ms)')
    print(f'  Late Layers:  {ns_values[6]:>10,} cycles ({ns_values[6]/110000:.1f} ms)')
    print(f'  Total:        {ns_values[7]:>10,} cycles ({ns_values[7]/110000:.1f} ms)')
    
    print(f'\nEnd-to-End:')
    print(f'  run_enclave(): {ns_values[8]:>10,} cycles ({ns_values[8]/110000:.1f} ms)')
    
    print(f'\nNS Memory Usage:')
    print(f'  Heap Used:  {ns_values[9]:>10,} bytes ({ns_values[9]/1024:.1f} KB)')
    print(f'  Heap Free:  {ns_values[10]:>10,} bytes ({ns_values[10]/1024:.1f} KB)')
    print(f'  Stack Used: {ns_values[11]:>10,} bytes ({ns_values[11]/1024:.1f} KB)')
    
    if ns_values[13] > 0:
        print(f'  RAM Used:   {ns_values[12]:>10,} / {ns_values[13]:,} bytes ({ns_values[12]/ns_values[13]*100:.1f}%)')
    else:
        print(f'  RAM Used:   {ns_values[12]:>10,} / {ns_values[13]:,} bytes (N/A)')
    
    if ns_values[15] > 0:
        print(f'  Flash Used: {ns_values[14]:>10,} / {ns_values[15]:,} bytes ({ns_values[14]/ns_values[15]*100:.1f}%)')
    else:
        print(f'  Flash Used: {ns_values[14]:>10,} / {ns_values[15]:,} bytes (N/A)')
    
    print(f'\nCounters:')
    print(f'  Inferences:   {ns_values[16]}')
    print(f'  Recreations:  {ns_values[17]}')
else:
    print(f'✗ NS data too short: {len(ns_data)} bytes (expected >= 72)')

# Parse Secure metrics
if len(s_data) >= 80:
    # Parse secure_benchmark_metrics_t
    # 3 x uint64_t (crypto ops) + 4 x uint64_t (counter mgmt) + 4 x uint32_t (counts) + 4 x uint32_t (memory)
    # = 7*8 + 8*4 = 56 + 32 = 88 bytes
    s_crypto = struct.unpack('<3Q', s_data[0:24])  # 3 uint64_t
    s_counter = struct.unpack('<4Q', s_data[24:56])  # 4 uint64_t
    s_counts = struct.unpack('<4I', s_data[56:72])  # 4 uint32_t
    s_memory = struct.unpack('<4I', s_data[72:88])  # 4 uint32_t
    
    print('\n' + '='*60)
    print('SECURE (S) BENCHMARK RESULTS')
    print('='*60)
    
    print(f'\nCryptographic Operations (Secure):')
    print(f'  AES Decrypt:    {s_crypto[0]:>10,} cycles ({s_crypto[0]/110000:.1f} ms) [{s_counts[0]} ops]')
    print(f'  Late Hash:      {s_crypto[1]:>10,} cycles ({s_crypto[1]/110000:.1f} ms) [{s_counts[1]} ops]')
    print(f'  Digest Compute: {s_crypto[2]:>10,} cycles ({s_crypto[2]/110000:.1f} ms) [{s_counts[2]} ops]')
    
    print(f'\nCounter Management (Secure):')
    print(f'  Get Max:        {s_counter[0]:>10,} cycles ({s_counter[0]/110000:.1f} ms)')
    print(f'  Check Allowed:  {s_counter[1]:>10,} cycles ({s_counter[1]/110000:.1f} ms)')
    print(f'  Increment:      {s_counter[2]:>10,} cycles ({s_counter[2]/110000:.1f} ms)')
    print(f'  Reset:          {s_counter[3]:>10,} cycles ({s_counter[3]/110000:.1f} ms)')
    print(f'  Total Ops:      {s_counts[3]}')
    
    print(f'\nSecure Memory Usage:')
    if s_memory[1] > 0:
        print(f'  RAM Used:   {s_memory[0]:>10,} / {s_memory[1]:,} bytes ({s_memory[0]/s_memory[1]*100:.1f}%)')
    else:
        print(f'  RAM Used:   {s_memory[0]:>10,} / {s_memory[1]:,} bytes (N/A)')
    
    if s_memory[3] > 0:
        print(f'  Flash Used: {s_memory[2]:>10,} / {s_memory[3]:,} bytes ({s_memory[2]/s_memory[3]*100:.1f}%)')
    else:
        print(f'  Flash Used: {s_memory[2]:>10,} / {s_memory[3]:,} bytes (N/A)')
    
    # Combined summary
    print('\n' + '='*60)
    print('COMBINED SYSTEM METRICS')
    print('='*60)
    total_ram = ns_values[13] + s_memory[1]
    total_ram_used = ns_values[12] + s_memory[0]
    total_flash = ns_values[15] + s_memory[3]
    total_flash_used = ns_values[14] + s_memory[2]
    
    if total_ram > 0:
        print(f'Total RAM:   {total_ram_used:>10,} / {total_ram:,} bytes ({total_ram_used/total_ram*100:.1f}%)')
    if total_flash > 0:
        print(f'Total Flash: {total_flash_used:>10,} / {total_flash:,} bytes ({total_flash_used/total_flash*100:.1f}%)')
else:
    print(f'✗ Secure data too short: {len(s_data)} bytes (expected >= 88)')

print('\n' + '='*60)

device.disconnect()
