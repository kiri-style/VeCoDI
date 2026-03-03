#!/usr/bin/env python3
"""Test script for split inference with enclave"""

import sys
sys.path.insert(0, 'tools')
import mac_provider
import struct

# Connect to device
device = mac_provider.STM32Device('/dev/cu.usbmodem1203', 115200)
if not device.connect():
    sys.exit(1)

provider = mac_provider.ModelProvider()
model_pub = bytes([0xC0 + i for i in range(32)])
model_secret = bytes([0xE0 + i for i in range(32)])
code_hash = bytes([0x01 + i for i in range(32)])
model_id = 0x00000001

print('\n' + '='*70)
print('TEST: ECDH → M_update → Split Inference (Early + Late Layers)')
print('='*70)

# Test 1: ECDH Handshake
print('\n[TEST 1] ECDH Handshake')
if mac_provider.perform_ecdh_handshake(device):
    print('✓ ECDH handshake successful')
else:
    print('✗ ECDH handshake failed')
    device.disconnect()
    sys.exit(1)

# Test 2: Check initial quota
print('\n[TEST 2] Initial Quota Check')
if device.send_command(mac_provider.CMD_GET_MAX_INFERENCES):
    resp = device.read_response()
    if resp and resp[0] == 0x00:
        max_inf = struct.unpack('<I', resp[1])[0]
        print(f'✓ Initial max_inferences: {max_inf}')
    else:
        print('✗ Failed')

# Test 3: Get EnclaveInfo
print('\n[TEST 3] Compute EnclaveInfo')
data = model_pub + model_secret + code_hash + struct.pack('<I', model_id)
if device.send_command(mac_provider.CMD_COMPUTE_ENCLAVE_INFO, data):
    resp = device.read_response()
    if resp and resp[0] == 0x00:
        enclave_info = resp[1]
        print(f'✓ EnclaveInfo: {enclave_info[:16].hex()}...')
    else:
        print('✗ Failed')

# Test 4: Send M_update with ECDH key
print('\n[TEST 4] Send M_update (c_limit=20) with ECDH key')
nonce, ciphertext, tag = provider.generate_m_update(20, enclave_info)
m_update_data = nonce + ciphertext + tag
if device.send_command(mac_provider.CMD_VALIDATE_M_UPDATE, m_update_data):
    resp = device.read_response()
    if resp and resp[0] == 0x00:
        print('✓ M_update validated')
    else:
        print('✗ M_update failed')

# Test 5: Check quota after M_update
print('\n[TEST 5] Quota After M_update')
if device.send_command(mac_provider.CMD_GET_MAX_INFERENCES):
    resp = device.read_response()
    if resp and resp[0] == 0x00:
        max_inf = struct.unpack('<I', resp[1])[0]
        print(f'✓ max_inferences: {max_inf}')

# Test 6: Run Split Inference (will call enclave)
print('\n[TEST 6] Run Split Inference (early layers + late layers)')
print('   This will:')
print('   - Create enclave in NS')
print('   - Call S to decrypt late layers with AES-256-GCM')
print('   - Execute early layers in NS')
print('   - Execute late layers with decrypted weights in NS')
print('   - Return result to Mac')
if device.send_command(mac_provider.CMD_RUN_INFERENCE):
    resp = device.read_response()
    if resp and resp[0] == 0x00:
        print('✓ Inference executed successfully!')
    else:
        print('✗ Inference failed')

# Test 7: Check quota after inference
print('\n[TEST 7] Quota After Inference')
if device.send_command(mac_provider.CMD_GET_INFERENCE_COUNT):
    resp = device.read_response()
    if resp and resp[0] == 0x00:
        count = struct.unpack('<I', resp[1])[0]
        print(f'✓ Inference count: {count}')

if device.send_command(mac_provider.CMD_GET_REMAINING_INFERENCES):
    resp = device.read_response()
    if resp and resp[0] == 0x00:
        remaining = struct.unpack('<I', resp[1])[0]
        print(f'✓ Remaining: {remaining}')

print('\n' + '='*70)
print('✓ SPLIT INFERENCE WITH ENCLAVE TEST COMPLETE!')
print('='*70)

device.disconnect()
