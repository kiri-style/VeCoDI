#!/usr/bin/env python3
import json
import struct
import sys
from pathlib import Path

from vecodi_case_study import UartDevice

PORT = '/dev/tty.usbmodem1203'
BAUD = 115200
CMD_GET_SECURE_BENCHMARK = 0x09
CPU_MHZ = 110.0


def main() -> int:
    device = UartDevice(PORT, BAUD)
    try:
        device.connect()
        device.send_command(CMD_GET_SECURE_BENCHMARK)
        status, payload = device.read_response(timeout=8.0)
        if status != 0:
            print(f'ERR device returned status {status}')
            return 1

        fmt = '<' + ('Q' * 18) + ('I' * 19)
        expected = struct.calcsize(fmt)
        if len(payload) < expected:
            print(f'ERR payload too short: got {len(payload)}, expected {expected}')
            return 1

        values = struct.unpack(fmt, payload[:expected])
        names = [
            'aes_decrypt_cycles', 'late_hash_cycles', 'digest_compute_cycles', 'm_update_cycles',
            'get_max_cycles', 'check_allowed_cycles', 'increment_cycles', 'reset_cycles',
            'create_enclave_cycles', 'finalize_create_cycles', 'destroy_enclave_cycles',
            'inf_start_cycles', 'inf_complete_cycles',
            'sau_sync_open_cycles', 'sau_sync_close_cycles', 'sau_flash_close_cycles',
            'sau_flash_open_cycles', 'sau_flash_pulse_cycles',
            'aes_decrypt_count', 'late_hash_count', 'digest_count', 'm_update_count',
            'counter_operations', 'create_enclave_count', 'finalize_create_count',
            'destroy_enclave_count', 'inf_start_count', 'inf_complete_count',
            'sau_sync_open_count', 'sau_sync_close_count', 'sau_flash_close_count',
            'sau_flash_open_count', 'sau_flash_pulse_count',
            'ram_used_bytes', 'ram_total_bytes', 'flash_used_bytes', 'flash_total_bytes',
        ]
        data = {name: int(value) for name, value in zip(names, values)}
        data['pox_cycles'] = data.get('inf_complete_cycles', 0)
        data['pox_count'] = data.get('inf_complete_count', 0)
        out_path = Path('build/secure_benchmark.json')
        out_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        print(f'[OK] Secure benchmark written: {out_path}')
        for key in ['m_update_cycles', 'create_enclave_cycles', 'pox_cycles', 'destroy_enclave_cycles', 'aes_decrypt_cycles']:
            cycles = data.get(key, 0)
            print(f'{key}: {cycles} cycles -> {cycles / (CPU_MHZ * 1000.0):.3f} ms')
        print(f"m_update_count: {data.get('m_update_count', 0)}")
        print(f"pox_count: {data.get('pox_count', 0)}")
        return 0
    finally:
        device.disconnect()


if __name__ == '__main__':
    sys.exit(main())
