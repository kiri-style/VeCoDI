#!/usr/bin/env python3
import json
import struct
import sys
from pathlib import Path

from vecodi_case_study import UartDevice

PORT = '/dev/tty.usbmodem1203'
BAUD = 115200
CMD_GET_TCB_BENCHMARK = 0x15


def main() -> int:
    device = UartDevice(PORT, BAUD)
    try:
        device.connect()
        device.send_command(CMD_GET_TCB_BENCHMARK)
        status, payload = device.read_response(timeout=8.0)
        if status != 0:
            print(f'ERR device returned status {status}')
            return 1

        fmt = '<6I'
        expected = struct.calcsize(fmt)
        if len(payload) < expected:
            print(f'ERR payload too short: got {len(payload)}, expected {expected}')
            return 1

        (
            secure_flash_used_bytes,
            secure_ram_used_bytes,
            model_ro_bytes,
            inference_ro_bytes,
            tcb_flash_bytes,
            tcb_total_bytes,
        ) = struct.unpack(fmt, payload[:expected])

        data = {
            'secure_flash_used_bytes': int(secure_flash_used_bytes),
            'secure_ram_used_bytes': int(secure_ram_used_bytes),
            'model_ro_bytes': int(model_ro_bytes),
            'inference_ro_bytes': int(inference_ro_bytes),
            'tcb_flash_bytes': int(tcb_flash_bytes),
            'tcb_total_bytes': int(tcb_total_bytes),
        }

        out_path = Path('build/tcb_benchmark.json')
        out_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        print(f'[OK] TCB benchmark written: {out_path}')
        print(f"secure_flash_used_bytes: {data['secure_flash_used_bytes']}")
        print(f"secure_ram_used_bytes: {data['secure_ram_used_bytes']}")
        print(f"model_ro_bytes: {data['model_ro_bytes']}")
        print(f"inference_ro_bytes: {data['inference_ro_bytes']}")
        print(f"tcb_flash_bytes: {data['tcb_flash_bytes']}")
        print(f"tcb_total_bytes: {data['tcb_total_bytes']}")
        return 0
    finally:
        device.disconnect()


if __name__ == '__main__':
    sys.exit(main())
