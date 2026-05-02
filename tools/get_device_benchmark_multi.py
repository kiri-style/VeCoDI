#!/usr/bin/env python3
"""
Multi-run Device Benchmark - Fetch & analyze 10 samples
"""
import struct
import importlib
import json
import time
from pathlib import Path

# Use backend Serial class directly
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
RUNS = 10

# field names in order from benchmark.h
names = [
    'enclave_create_cycles','enclave_destroy_cycles','aes_decrypt_cycles',
    'early_layers_cycles','late_layers_cycles','total_inference_cycles','run_enclave_cycles','full_execute_cycles',
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
    'full_execute_count','full_execute_sum_cycles','full_execute_min_cycles','full_execute_max_cycles',
    'create_atomic_sum_cycles','destroy_atomic_sum_cycles',
    'create_atomic_min_cycles','create_atomic_max_cycles','destroy_atomic_min_cycles','destroy_atomic_max_cycles','create_atomic_count','destroy_atomic_count',
    'run_inference_with_image_count','dangerous_inference_no_sau_count','dangerous_read_ram_count','dangerous_read_rom_count'
]

    fmt = '<' + 'I'*19 + 'xxxx' + 'Q'*8 + 'I'*16 + 'I'*8 + 'I' + 'xxxx' + 'Q' + 'I'*2 + 'Q'*2 + 'I'*6 + 'I'*4
expected = struct.calcsize(fmt)

def fetch_device_benchmark():
    """Fetch one benchmark sample from device"""
    try:
        ser = Serial(PORT, BAUD, timeout=6, write_timeout=2)
    except Exception as e:
        print('  ERR open serial:', e)
        return None

    try:
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        ser.write(struct.pack('<BI', CMD, 0))
        ser.flush()

        st = ser.read(1)
        if len(st) != 1:
            print('  No status byte')
            return None
        status = st[0]
        
        llen = ser.read(4)
        if len(llen) != 4:
            print('  No length')
            return None
        L = struct.unpack('<I', llen)[0]
        
        if status != 0 or L == 0:
            print(f'  Status={hex(status)}, len={L}')
            return None

        data = ser.read(L)
        if len(data) != L:
            print(f'  Truncated: expected {L}, got {len(data)}')
            return None

        if expected != L:
            print(f'  Warning: expected size {expected}, got {L}')
        
        buf = data[:expected]
        vals = struct.unpack(fmt, buf)
        out = {n: int(v) for n, v in zip(names, vals)}
        return out
    finally:
        ser.close()


print(f"\n=== Device Benchmark {RUNS} Runs ===\n")
results = []
errors = 0

for i in range(RUNS):
    print(f"Run {i+1:2d}/{RUNS}...", end=' ', flush=True)
    result = fetch_device_benchmark()
    if result:
        results.append(result)
        print(f"✓ (create={result['enclave_create_cycles']:,})")
    else:
        print("✗")
        errors += 1
    time.sleep(0.5)

print(f"\n✓ Successful: {len(results)}/{RUNS}, ✗ Failed: {errors}\n")

if not results:
    print("No successful runs!")
    sys.exit(1)

# Compute statistics for key metrics
stats = {}
for name in names:
    values = [r[name] for r in results if name in r]
    if not values:
        continue
    mean = sum(values) / len(values)
    variance = sum((x - mean)**2 for x in values) / len(values)
    stddev = variance ** 0.5 if variance > 0 else 0
    stats[name] = {
        'mean': mean,
        'min': min(values),
        'max': max(values),
        'stddev': stddev,
    }

# Pretty print key metrics
print("KEY METRICS (mean ± stddev):")
print("-" * 75)
key_metrics = [
    'enclave_create_cycles', 'enclave_destroy_cycles', 'aes_decrypt_cycles',
    'early_layers_cycles', 'late_layers_cycles', 'total_inference_cycles',
    'inference_count', 'enclave_recreations'
]
for metric in key_metrics:
    if metric in stats:
        s = stats[metric]
        print(f"{metric:33s}: {s['mean']:15,.0f} ± {s['stddev']:10,.0f} (min={s['min']:,}, max={s['max']:,})")

# Save aggregated results
output = {
    'runs': RUNS,
    'successful': len(results),
    'failed': errors,
    'raw_samples': results,
    'statistics': {k: {'mean': v['mean'], 'min': v['min'], 'max': v['max'], 'stddev': v['stddev']} for k, v in stats.items()}
}

out_path = 'build/device_benchmark_multi.json'
Path('build').mkdir(parents=True, exist_ok=True)
with open(out_path, 'w', encoding='utf-8') as fh:
    json.dump(output, fh, indent=2)

print(f"\n[OK] Multi-run benchmark saved: {out_path}")
