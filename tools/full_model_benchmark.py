#!/usr/bin/env python3
"""
Full Model Benchmark: create → inference → destroy

Measures 3 core operations (10 runs each)
"""
import argparse
import json
import struct
import sys
import time
from pathlib import Path
from statistics import mean, stdev

import serial

try:
    from serial.serialposix import Serial as _SerialClass
except Exception:
    try:
        from serial.serialwin32 import Serial as _SerialClass
    except Exception:
        _SerialClass = None

PORT_DEFAULT = '/dev/tty.usbmodem1203'
BAUD_DEFAULT = 115200

# Commands
CMD_CREATE_ENCLAVE = 0x11
CMD_DESTROY_ENCLAVE = 0x12
CMD_RUN_INFERENCE = 0x04
CMD_GET_BENCHMARK = 0x08

DEVICE_BENCHMARK_NAMES = [
    'enclave_create_cycles', 'enclave_destroy_cycles', 'aes_decrypt_cycles',
    'early_layers_cycles', 'late_layers_cycles', 'total_inference_cycles', 'run_enclave_cycles',
    'heap_used_bytes', 'heap_free_bytes', 'stack_used_bytes',
    'ram_used_bytes', 'ram_total_bytes', 'flash_used_bytes', 'flash_total_bytes',
    'inference_count', 'enclave_recreations', 'inference_requests_total', 'enclave_info_validation_failures',
    'enclave_create_sum_cycles', 'enclave_destroy_sum_cycles', 'aes_decrypt_sum_cycles',
    'early_layers_sum_cycles', 'late_layers_sum_cycles', 'total_inference_sum_cycles', 'run_enclave_sum_cycles', 'irq_atomic_sum_cycles',
    'enclave_create_min_cycles', 'enclave_create_max_cycles', 'enclave_destroy_min_cycles', 'enclave_destroy_max_cycles',
    'aes_decrypt_min_cycles', 'aes_decrypt_max_cycles', 'early_layers_min_cycles', 'early_layers_max_cycles',
    'late_layers_min_cycles', 'late_layers_max_cycles', 'total_inference_min_cycles', 'total_inference_max_cycles',
    'run_enclave_min_cycles', 'run_enclave_max_cycles', 'irq_atomic_min_cycles', 'irq_atomic_max_cycles',
    'enclave_create_count', 'enclave_destroy_count', 'aes_decrypt_count', 'early_layers_count', 'late_layers_count', 'total_inference_count', 'run_enclave_count', 'irq_atomic_count',
    'create_atomic_sum_cycles', 'destroy_atomic_sum_cycles',
    'create_atomic_min_cycles', 'create_atomic_max_cycles', 'destroy_atomic_min_cycles', 'destroy_atomic_max_cycles', 'create_atomic_count', 'destroy_atomic_count',
    'run_inference_with_image_count', 'dangerous_inference_no_sau_count', 'dangerous_read_ram_count', 'dangerous_read_rom_count',
]
DEVICE_BENCHMARK_FMT = '<' + 'I' * 18 + 'Q' * 8 + 'I' * 16 + 'I' * 8 + 'Q' * 2 + 'I' * 6 + 'I' * 4


class UartDevice:
    def __init__(self, port: str, baudrate: int) -> None:
        self.port = port
        self.baudrate = baudrate
        self.ser = None

    def connect(self) -> None:
        if _SerialClass is not None:
            self.ser = _SerialClass(self.port, self.baudrate, timeout=8.0, write_timeout=5.0)
        else:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=8.0, write_timeout=5.0)
        time.sleep(2.5)
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()

    def disconnect(self) -> None:
        if self.ser and self.ser.is_open:
            self.ser.close()

    def send_command(self, cmd: int, payload: bytes = b'') -> None:
        if not self.ser or not self.ser.is_open:
            raise RuntimeError('Serial port not open')
        packet = struct.pack('<BI', cmd, len(payload)) + payload
        self.ser.reset_input_buffer()
        self.ser.write(packet)
        self.ser.flush()

    def read_response(self, timeout: float = 8.0):
        if not self.ser or not self.ser.is_open:
            raise RuntimeError('Serial port not open')

        old_timeout = self.ser.timeout
        self.ser.timeout = timeout
        try:
            status_raw = self.ser.read(1)
            if len(status_raw) != 1:
                raise TimeoutError('Timeout reading status byte')
            status = status_raw[0]

            len_raw = self.ser.read(4)
            if len(len_raw) != 4:
                raise TimeoutError('Timeout reading length')
            length = struct.unpack('<I', len_raw)[0]

            data = b''
            if length:
                data = self.ser.read(length)
                if len(data) != length:
                    raise TimeoutError(f'Payload truncated: expected {length}, got {len(data)}')
            return status, data
        finally:
            self.ser.timeout = old_timeout


def read_device_benchmark(device: UartDevice) -> dict:
    device.send_command(CMD_GET_BENCHMARK)
    status, payload = device.read_response(timeout=8.0)
    if status != 0:
        raise RuntimeError(f'CMD_GET_BENCHMARK failed with status {status}')

    expected = struct.calcsize(DEVICE_BENCHMARK_FMT)
    if len(payload) < expected:
        raise RuntimeError(f'Benchmark payload too short: got {len(payload)}, expected {expected}')

    values = struct.unpack(DEVICE_BENCHMARK_FMT, payload[:expected])
    return {name: int(value) for name, value in zip(DEVICE_BENCHMARK_NAMES, values)}


def send_create(device: UartDevice) -> float:
    started = time.perf_counter()
    device.send_command(CMD_CREATE_ENCLAVE, b'')
    status, response = device.read_response(timeout=12.0)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if status != 0:
        detail = None
        if len(response) >= 4:
            detail = struct.unpack('<i', response[:4])[0]
        raise RuntimeError(f'CREATE_ENCLAVE failed (status={status}, detail={detail})')
    return elapsed_ms


def send_run_inference(device: UartDevice) -> float:
    started = time.perf_counter()
    device.send_command(CMD_RUN_INFERENCE, b'')
    status, response = device.read_response(timeout=12.0)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if status != 0:
        detail = None
        if len(response) >= 4:
            detail = struct.unpack('<i', response[:4])[0]
        raise RuntimeError(f'RUN_INFERENCE failed (status={status}, detail={detail})')
    return elapsed_ms


def send_destroy(device: UartDevice) -> float:
    started = time.perf_counter()
    device.send_command(CMD_DESTROY_ENCLAVE, b'')
    status, response = device.read_response(timeout=8.0)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if status != 0:
        detail = None
        if len(response) >= 4:
            detail = struct.unpack('<i', response[:4])[0]
        raise RuntimeError(f'DESTROY_ENCLAVE failed (status={status}, detail={detail})')
    return elapsed_ms


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Benchmark full model: create → inference → destroy')
    parser.add_argument('port', nargs='?', default=PORT_DEFAULT, help=f'Serial device (default: {PORT_DEFAULT})')
    parser.add_argument('--baud', type=int, default=BAUD_DEFAULT, help=f'UART baudrate (default: {BAUD_DEFAULT})')
    parser.add_argument('--runs', type=int, default=10, help='Number of full cycles (default: 10)')
    parser.add_argument('--output', type=str, default=None, help='Optional JSON output path')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.runs <= 0:
        raise ValueError('--runs must be > 0')

    output_path = Path(args.output) if args.output else Path(__file__).resolve().parents[1] / 'build' / 'full_model_benchmark.json'

    device = UartDevice(args.port, args.baud)
    samples = []

    try:
        device.connect()
        for run in range(args.runs):
            try:
                # Step 1: CREATE
                host_create_ms = send_create(device)
                after_create = read_device_benchmark(device)

                # Step 2: RUN INFERENCE
                host_inference_ms = send_run_inference(device)
                after_inference = read_device_benchmark(device)

                # Step 3: DESTROY
                host_destroy_ms = send_destroy(device)
                after_destroy = read_device_benchmark(device)

                samples.append({
                    'attempt': run + 1,
                    'host_create_ms': round(host_create_ms, 3),
                    'create_enc_cycles': int(after_create['enclave_create_cycles']),
                    'host_inference_ms': round(host_inference_ms, 3),
                    'total_inference_cycles': int(after_inference['total_inference_cycles']),
                    'early_layers_cycles': int(after_inference['early_layers_cycles']),
                    'late_layers_cycles': int(after_inference['late_layers_cycles']),
                    'host_destroy_ms': round(host_destroy_ms, 3),
                    'destroy_enc_cycles': int(after_destroy['enclave_destroy_cycles']),
                })
                print(f"  Run {run + 1:2d}: create={host_create_ms:6.2f}ms, inference={host_inference_ms:6.2f}ms, destroy={host_destroy_ms:5.2f}ms")

            except Exception as e:
                print(f"  Run {run + 1}: ERROR - {e}", file=sys.stderr)
                raise

        # Compute statistics
        result = {
            'port': args.port,
            'baud': args.baud,
            'runs': int(args.runs),
            'samples': samples,
            'create_cycles_mean': round(mean(sample['create_enc_cycles'] for sample in samples), 1),
            'create_cycles_stddev': round(stdev(sample['create_enc_cycles'] for sample in samples), 1) if len(samples) > 1 else 0.0,
            'create_ms_mean': round(mean(sample['host_create_ms'] for sample in samples), 3),
            'create_ms_stddev': round(stdev(sample['host_create_ms'] for sample in samples), 3) if len(samples) > 1 else 0.0,
            'inference_cycles_mean': round(mean(sample['total_inference_cycles'] for sample in samples), 1),
            'inference_cycles_stddev': round(stdev(sample['total_inference_cycles'] for sample in samples), 1) if len(samples) > 1 else 0.0,
            'inference_ms_mean': round(mean(sample['host_inference_ms'] for sample in samples), 3),
            'inference_ms_stddev': round(stdev(sample['host_inference_ms'] for sample in samples), 3) if len(samples) > 1 else 0.0,
            'early_layers_cycles_mean': round(mean(sample['early_layers_cycles'] for sample in samples), 1),
            'late_layers_cycles_mean': round(mean(sample['late_layers_cycles'] for sample in samples), 1),
            'destroy_cycles_mean': round(mean(sample['destroy_enc_cycles'] for sample in samples), 1),
            'destroy_cycles_stddev': round(stdev(sample['destroy_enc_cycles'] for sample in samples), 1) if len(samples) > 1 else 0.0,
            'destroy_ms_mean': round(mean(sample['host_destroy_ms'] for sample in samples), 3),
            'destroy_ms_stddev': round(stdev(sample['host_destroy_ms'] for sample in samples), 3) if len(samples) > 1 else 0.0,
        }

        # Print summary
        print(f"\n=== FULL MODEL BENCHMARK SUMMARY ({args.runs} runs) ===")
        print(f"CREATE:    {result['create_ms_mean']:.3f} ± {result['create_ms_stddev']:.3f} ms ({int(result['create_cycles_mean']):,} ± {int(result['create_cycles_stddev'])} cycles)")
        print(f"INFERENCE: {result['inference_ms_mean']:.3f} ± {result['inference_ms_stddev']:.3f} ms ({int(result['inference_cycles_mean']):,} ± {int(result['inference_cycles_stddev'])} cycles)")
        print(f"  → early_layers:  {int(result['early_layers_cycles_mean']):,} cycles")
        print(f"  → late_layers:   {int(result['late_layers_cycles_mean']):,} cycles")
        print(f"DESTROY:   {result['destroy_ms_mean']:.3f} ± {result['destroy_ms_stddev']:.3f} ms ({int(result['destroy_cycles_mean']):,} ± {int(result['destroy_cycles_stddev'])} cycles)")
        print(f"============================================\n")

        # Save JSON
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[OK] full_model_benchmark written: {output_path}")

        return 0

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    finally:
        device.disconnect()


if __name__ == '__main__':
    sys.exit(main())
