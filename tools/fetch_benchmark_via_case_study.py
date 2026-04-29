#!/usr/bin/env python3
import importlib.machinery, importlib.util, sys, struct, json
from pathlib import Path

module_path = Path(__file__).parent / 'vecodi_case_study.py'
loader = importlib.machinery.SourceFileLoader('vecodi_case_study', str(module_path))
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

# UartDevice class is now available as mod.UartDevice
PORT = '/dev/tty.usbmodem1203'
BAUD = 115200
CMD_GET_BENCHMARK = 0x08

device = mod.UartDevice(PORT, BAUD)
try:
    device.connect()
    device.send_command(CMD_GET_BENCHMARK)
    status, payload = device.read_response(timeout=6.0)
    if status != mod.RESP_OK:
        print('Device returned error status', status)
        sys.exit(1)
    L = len(payload)
    print('len', L)
    # same parsing as benchmark parser
    fmt = '<' + 'I'*18 + 'Q'*8 + 'I'*16 + 'I'*8 + 'Q'*2 + 'I'*6 + 'I'*4
    import struct as _s
    expected = _s.calcsize(fmt)
    if L < expected:
        print('Payload too short', L, 'expected', expected)
        sys.exit(1)
    vals = _s.unpack(fmt, payload[:expected])
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
    out = {n:int(v) for n,v in zip(names, vals)}
    out_path = 'build/device_benchmark.json'
    Path('build').mkdir(parents=True, exist_ok=True)
    with open(out_path,'w',encoding='utf-8') as fh:
        json.dump(out, fh, indent=2)
    print('[OK] Device benchmark saved to', out_path)
finally:
    device.disconnect()
