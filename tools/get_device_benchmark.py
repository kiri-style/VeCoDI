#!/usr/bin/env python3
import struct
import importlib
# Use backend Serial class directly to avoid top-level namespace issues
try:
    mod_sp = importlib.import_module('serial.serialposix')
    Serial = getattr(mod_sp, 'Serial')
except Exception:
    try:
        mod_sw = importlib.import_module('serial.serialwin32')
        Serial = getattr(mod_sw, 'Serial')
    except Exception as e:
        print('ERR importing serial backend:', e)
        raise
import sys

PORT = '/dev/tty.usbmodem1203'
BAUD = 115200
CMD = 0x08

try:
    ser = Serial(PORT, BAUD, timeout=6, write_timeout=2)
except Exception as e:
    print('ERR open serial:', e)
    sys.exit(2)

ser.reset_input_buffer(); ser.reset_output_buffer()
ser.write(struct.pack('<BI', CMD, 0))
ser.flush()

st = ser.read(1)
if len(st) != 1:
    print('No status byte')
    sys.exit(1)
status = st[0]
llen = ser.read(4)
if len(llen) != 4:
    print('No length')
    sys.exit(1)
L = struct.unpack('<I', llen)[0]
print('status=', hex(status), 'len=', L)
if status != 0 or L == 0:
    data = ser.read(L) if L else b''
    print('error or empty, raw=', data)
    ser.close(); sys.exit(0)

data = ser.read(L)
if len(data) != L:
    print('truncated payload', len(data)); ser.close(); sys.exit(1)

# field names in order from benchmark.h
names = [
    'enclave_create_cycles','enclave_destroy_cycles','aes_decrypt_cycles',
    'early_layers_cycles','late_layers_cycles','total_inference_cycles','run_enclave_cycles',
    'heap_used_bytes','heap_free_bytes','stack_used_bytes',
    'ram_used_bytes','ram_total_bytes','flash_used_bytes','flash_total_bytes',
    'inference_count','enclave_recreations','inference_requests_total','enclave_info_validation_failures',
    'enclave_create_sum_cycles','enclave_destroy_sum_cycles','aes_decrypt_sum_cycles',
    'early_layers_sum_cycles','late_layers_sum_cycles','total_inference_sum_cycles','run_enclave_sum_cycles','irq_atomic_sum_cycles',
    'enclave_create_min_cycles','enclave_create_max_cycles','enclave_destroy_min_cycles','enclave_destroy_max_cycles',
    'aes_decrypt_min_cycles','aes_decrypt_max_cycles','early_layers_min_cycles','early_layers_max_cycles',
    'late_layers_min_cycles','late_layers_max_cycles','total_inference_min_cycles','total_inference_max_cycles',
    'run_enclave_min_cycles','run_enclave_max_cycles','irq_atomic_min_cycles','irq_atomic_max_cycles',
    'enclave_create_count','enclave_destroy_count','aes_decrypt_count','early_layers_count','late_layers_count','total_inference_count','run_enclave_count','irq_atomic_count',
    'create_atomic_sum_cycles','destroy_atomic_sum_cycles',
    'create_atomic_min_cycles','create_atomic_max_cycles','destroy_atomic_min_cycles','destroy_atomic_max_cycles','create_atomic_count','destroy_atomic_count',
    'run_inference_with_image_count','dangerous_inference_no_sau_count','dangerous_read_ram_count','dangerous_read_rom_count'
]

fmt = '<' + 'I'*18 + 'Q'*8 + 'I'*16 + 'I'*8 + 'Q'*2 + 'I'*6 + 'I'*4
expected = struct.calcsize(fmt)
if expected != L:
    print(f'Warning: expected size {expected}, got {L} -- will try to parse available bytes')
# truncate or pad data as needed
buf = data[:expected]
vals = struct.unpack(fmt, buf)
import json
out = {n: int(v) for n, v in zip(names, vals)}
out_path = 'build/device_benchmark.json'
try:
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(out, fh, indent=2)
    print(f'[OK] Device benchmark written: {out_path}')
except Exception as e:
    print('ERR writing json', e)

ser.close()
