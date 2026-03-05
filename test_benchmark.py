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

# Step 5: Get benchmark metrics
print('[5] Retrieving benchmark metrics...')
if not device.send_command(0x08):  # CMD_GET_BENCHMARK
    print('✗ Failed to send')
    device.disconnect()
    sys.exit(1)

resp = device.read_response()
if not resp or resp[0] != 0x00:
    print(f'✗ Failed (status {resp[0] if resp else "None"})')
    device.disconnect()
    sys.exit(1)

data = resp[1]
print(f'✓ Received {len(data)} bytes')

if len(data) >= 112:
    # Parse benchmark_metrics_t
    values = struct.unpack('<28I', data[:112])
    
    print('\n' + '='*60)
    print('BENCHMARK RESULTS FROM DEVICE')
    print('='*60)
    
    print(f'\nEnclave Lifecycle:')
    print(f'  Create:  {values[0]:>10,} cycles ({values[0]/110000:.1f} ms)')
    print(f'  Destroy: {values[1]:>10,} cycles ({values[1]/110000:.1f} ms)')
    
    print(f'\nCryptographic Operations:')
    print(f'  AES Decrypt:    {values[2]:>10,} cycles ({values[2]/110000:.1f} ms)')
    print(f'  Late Hash:      {values[3]:>10,} cycles ({values[3]/110000:.1f} ms)')
    print(f'  Inference Hash: {values[4]:>10,} cycles ({values[4]/110000:.1f} ms)')
    
    print(f'\nInference Performance:')
    print(f'  Early Layers: {values[5]:>10,} cycles ({values[5]/110000:.1f} ms)')
    print(f'  Late Layers:  {values[6]:>10,} cycles ({values[6]/110000:.1f} ms)')
    print(f'  Total:        {values[7]:>10,} cycles ({values[7]/110000:.1f} ms)')
    
    print(f'\nEnd-to-End:')
    print(f'  run_enclave(): {values[8]:>10,} cycles ({values[8]/110000:.1f} ms)')
    
    print(f'\nMemory Usage:')
    print(f'  Heap Used:  {values[9]:>10,} bytes ({values[9]/1024:.1f} KB)')
    print(f'  Heap Free:  {values[10]:>10,} bytes ({values[10]/1024:.1f} KB)')
    print(f'  Stack Used: {values[11]:>10,} bytes ({values[11]/1024:.1f} KB)')
    print(f'  RAM Used:   {values[12]:>10,} / {values[13]:,} bytes ({values[12]/values[13]*100:.1f}%)')
    print(f'  Flash Used: {values[14]:>10,} / {values[15]:,} bytes ({values[14]/values[15]*100:.1f}%)')
    
    print(f'\nCounters:')
    print(f'  Inferences:   {values[16]}')
    print(f'  Recreations:  {values[17]}')
    
    print('\n' + '='*60)
else:
    print(f'✗ Data too short: {len(data)} bytes (expected >= 112)')

device.disconnect()
