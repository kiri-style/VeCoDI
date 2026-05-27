#!/usr/bin/env python3
import argparse
import json
import struct
import sys
import time
from statistics import mean, stdev
from pathlib import Path

import serial

try:
    from serial.serialposix import Serial as _SerialClass
except Exception:
    try:
        from serial.serialwin32 import Serial as _SerialClass
    except Exception:
        _SerialClass = None


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

    def send_command(self, cmd: int, payload: bytes = b"") -> None:
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

PORT_DEFAULT = '/dev/cu.usbmodem1203'
BAUD_DEFAULT = 115200
CMD_CREATE_ENCLAVE = 0x11
CMD_DESTROY_ENCLAVE = 0x12
CMD_GET_BENCHMARK = 0x08
CMD_GET_SECURE_BENCHMARK = 0x09
DEVICE_BENCHMARK_NAMES = [
    'enclave_create_cycles', 'enclave_destroy_cycles', 'aes_decrypt_cycles',
    'early_layers_cycles', 'late_layers_cycles', 'total_inference_cycles', 'run_enclave_cycles', 'full_execute_cycles',
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
    'full_execute_count', 'full_execute_sum_cycles', 'full_execute_min_cycles', 'full_execute_max_cycles',
    'create_atomic_sum_cycles', 'destroy_atomic_sum_cycles',
    'create_atomic_min_cycles', 'create_atomic_max_cycles', 'destroy_atomic_min_cycles', 'destroy_atomic_max_cycles', 'create_atomic_count', 'destroy_atomic_count',
    'run_inference_with_image_count', 'dangerous_inference_no_sau_count', 'dangerous_read_ram_count', 'dangerous_read_rom_count',
    'm_update_cycles', 'm_update_count',
]
ORIGINAL_DEVICE_BENCHMARK_FMT = '<' + 'I' * 19 + 'xxxx' + 'Q' * 8 + 'I' * 16 + 'I' * 8 + 'I' + 'xxxx' + 'Q' + 'I' * 2 + 'Q' * 2 + 'I' * 6 + 'I' * 4 + 'xxxxQI'
DEVICE_BENCHMARK_FMT = ORIGINAL_DEVICE_BENCHMARK_FMT
SECURE_BENCHMARK_NAMES = [
    'aes_decrypt_cycles', 'late_hash_cycles', 'digest_compute_cycles', 'authorize_cycles', 'global_crypto_init_cycles',
    'create_validate_cycles', 'authorize_parse_cycles', 'authorize_verify_cycles', 'authorize_update_cycles', 'authorize_crypto_init_cycles',
    'authorize_read_cycles', 'authorize_import_key_cycles', 'authorize_hash_msg_cycles', 'authorize_verify_sig_cycles', 'authorize_destroy_key_cycles',
    'authorize_verify_message_cycles', 'authorize_verify_old_cycles', 'create_recompute_cycles',
    'get_max_cycles', 'check_allowed_cycles', 'increment_cycles', 'reset_cycles',
    'create_enclave_cycles', 'finalize_create_cycles', 'destroy_enclave_cycles', 'inf_start_cycles', 'inf_complete_cycles',
    'sau_sync_open_cycles', 'sau_sync_close_cycles', 'sau_flash_close_cycles', 'sau_flash_open_cycles', 'sau_flash_pulse_cycles',
    'aes_decrypt_count', 'late_hash_count', 'digest_count', 'authorize_count', 'authorize_crypto_init_count',
    'authorize_import_key_count', 'authorize_verify_sig_count', 'authorize_verify_message_count', 'create_recompute_count', 'counter_operations',
    'create_enclave_count', 'finalize_create_count', 'destroy_enclave_count', 'inf_start_count', 'inf_complete_count',
    'sau_sync_open_count', 'sau_sync_close_count', 'sau_flash_close_count', 'sau_flash_open_count', 'sau_flash_pulse_count',
    'ram_used_bytes', 'ram_total_bytes', 'flash_used_bytes', 'flash_total_bytes',
]
SECURE_BENCHMARK_FMT = '<' + ('Q' * 32) + ('I' * 24)
# Append secure metric names to the device benchmark names so the single
# CMD_GET_BENCHMARK payload contains both NS and Secure metrics. The
# DEVICE_BENCHMARK_FMT must also be extended with the secure-format tail.
DEVICE_BENCHMARK_NAMES += ['secure_' + name for name in SECURE_BENCHMARK_NAMES]
# Extend the unpack format by concatenating the inner part of
# SECURE_BENCHMARK_FMT (strip leading '<').
DEVICE_BENCHMARK_FMT = DEVICE_BENCHMARK_FMT + SECURE_BENCHMARK_FMT[1:]
CPU_MHZ = 110.0


def delta(after: dict, before: dict, key: str) -> int:
    # Safely compute delta even if the key is missing (old firmware returns
    # the shorter NS-only payload). Missing secure keys will be treated as 0.
    return int(after.get(key, 0)) - int(before.get(key, 0))


def per_op_cycles(after: dict, before: dict, sum_key: str, count_key: str, fallback_key: str) -> int:
    count_delta = delta(after, before, count_key)
    if count_delta > 0:
        sum_delta = delta(after, before, sum_key)
        return int(round(sum_delta / count_delta))
    # Avoid returning spurious large fallback deltas when no ops were counted.
    return 0


def print_breakdown(size_bytes, secure_metrics):
    """Affiche breakdown formaté avec les vraies métriques Secure."""

    create_total = int(secure_metrics.get('secure_create_total', 0))
    destroy_total = int(secure_metrics.get('secure_destroy_total', 0))

    if create_total == 0:
        print(f"[WARN] Secure metrics not available for size {size_bytes}")
        return

    enclave_recalc_cycles = int(secure_metrics.get('secure_create_recompute', 0))
    aes_decrypt_cycles = int(secure_metrics.get('secure_aes_decrypt', 0))
    # Use explicit SAU registration metric when available to avoid residual-based
    # computations that can cause inconsistencies with other reports.
    sau_registration_cycles = int(secure_metrics.get('secure_create_validate', 0))

    sau_restore_cycles = int(secure_metrics.get('secure_destroy_sau_open', 0))
    if sau_restore_cycles == 0:
        sau_restore_cycles = int(secure_metrics.get('secure_destroy_sau_close', 0))
    memory_zeroization_cycles = max(destroy_total - sau_restore_cycles, 0)

    print(f"\n========== SIZE: {size_bytes} bytes ==========")
    print("")

    print(f"Create - {create_total:,} cycles total")
    # Aggregate SAU + validation: `create_validate_cycles` contains both the
    # recompute (EnclaveInfo recalc) and the memcmp-based validation cost.
    create_validate_cycles = sau_registration_cycles
    validation_memcmp = max(create_validate_cycles - enclave_recalc_cycles, 0)

    # Use a stable denominator for percentages: prefer the measured total,
    # but if components sum to more than the reported total (or total is 0),
    # use the components sum to avoid >100% artifacts.
    comp_sum = aes_decrypt_cycles + create_validate_cycles
    denom_create = max(create_total, comp_sum, 1)

    pct = (aes_decrypt_cycles / denom_create * 100)
    print(f"├── AES decrypt        : {aes_decrypt_cycles:,} cycles   [{pct:.1f}%]  ← bottleneck")

    pct = (create_validate_cycles / denom_create * 100)
    print(f"└── SAU + validation   : {create_validate_cycles:,} cycles   [{pct:.1f}%]")
    print(f"    ├── EnclaveInfo recalc : {enclave_recalc_cycles:,} cycles")
    print(f"    └── Validation memcmp  : {validation_memcmp:,} cycles")

    print("")
    print(f"Destroy - {destroy_total:,} cycles total")
    # If destroy_total is zero but we observed SAU restore cycles, use the
    # observed component for percentage denominator to avoid divide-by-zero
    # and to show meaningful percentages instead of misleading zeros.
    denom_destroy = max(destroy_total, sau_restore_cycles, 1)
    pct = (memory_zeroization_cycles / denom_destroy * 100)
    print(f"├── Memory zeroization : {memory_zeroization_cycles:,} cycles   [{pct:.1f}%]  ← bottleneck")
    pct = (sau_restore_cycles / denom_destroy * 100)
    print(f"└── SAU restore        : {sau_restore_cycles:,} cycles   [{pct:.1f}%]")


def read_device_benchmark(device: UartDevice) -> dict:
    attempts = 3
    full_expected = struct.calcsize(DEVICE_BENCHMARK_FMT)
    base_expected = struct.calcsize(ORIGINAL_DEVICE_BENCHMARK_FMT)
    last_error = None

    for _ in range(attempts):
        try:
            device.send_command(CMD_GET_BENCHMARK)
            status, payload = device.read_response(timeout=6.0)
            if status != 0:
                last_error = RuntimeError(f'CMD_GET_BENCHMARK failed with status {status}')
                time.sleep(0.05)
                continue
            # If the device returns the shorter, original (NS-only) payload,
            # fall back to that format and return only the matching metric names.
            if len(payload) < full_expected:
                if len(payload) < base_expected:
                    raise RuntimeError(f'Benchmark payload too short: got {len(payload)}, expected at least {base_expected}')
                values = struct.unpack(ORIGINAL_DEVICE_BENCHMARK_FMT, payload[:base_expected])
                return {name: int(value) for name, value in zip(DEVICE_BENCHMARK_NAMES, values)}

            values = struct.unpack(DEVICE_BENCHMARK_FMT, payload[:full_expected])
            return {name: int(value) for name, value in zip(DEVICE_BENCHMARK_NAMES, values)}
        except Exception as exc:
            last_error = exc
            time.sleep(0.05)

    raise RuntimeError(f'Failed to read device benchmark after retries: {last_error}')


def read_secure_benchmark(device: UartDevice) -> dict:
    """Read Secure partition benchmark via dedicated CMD_GET_SECURE_BENCHMARK.

    Returns a dict mapping SECURE_BENCHMARK_NAMES -> values.
    """
    attempts = 3
    expected = struct.calcsize(SECURE_BENCHMARK_FMT)
    last_error = None

    for _ in range(attempts):
        try:
            device.send_command(CMD_GET_SECURE_BENCHMARK)
            status, payload = device.read_response(timeout=6.0)
            if status != 0:
                last_error = RuntimeError(f'CMD_GET_SECURE_BENCHMARK failed with status {status}')
                time.sleep(0.05)
                continue
            if len(payload) < expected:
                raise RuntimeError(f'Secure benchmark payload too short: got {len(payload)}, expected {expected}')
            values = struct.unpack(SECURE_BENCHMARK_FMT, payload[:expected])
            return {name: int(value) for name, value in zip(SECURE_BENCHMARK_NAMES, values)}
        except Exception as exc:
            last_error = exc
            time.sleep(0.05)

    raise RuntimeError(f'Failed to read secure benchmark after retries: {last_error}')


def send_create(device: UartDevice, decrypt_size: int) -> tuple[int, float]:
    payload = struct.pack('<I', decrypt_size) if decrypt_size > 0 else b''
    started = time.perf_counter()
    device.send_command(CMD_CREATE_ENCLAVE, payload)
    status, response = device.read_response(timeout=10.0)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if status != 0:
        detail = None
        if len(response) >= 4:
            detail = struct.unpack('<i', response[:4])[0]
        raise RuntimeError(f'CREATE_ENCLAVE failed for size {decrypt_size} (status={status}, detail={detail})')
    return status, elapsed_ms


def send_destroy(device: UartDevice) -> tuple[int, float]:
    started = time.perf_counter()
    device.send_command(CMD_DESTROY_ENCLAVE)
    status, response = device.read_response(timeout=8.0)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if status != 0:
        detail = None
        if len(response) >= 4:
            detail = struct.unpack('<i', response[:4])[0]
        raise RuntimeError(f'DESTROY_ENCLAVE failed (status={status}, detail={detail})')
    return status, elapsed_ms


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Benchmark CREATE_ENCLAVE with variable decrypt sizes',
    )
    parser.add_argument('port', nargs='?', default=PORT_DEFAULT, help=f'Serial device (default: {PORT_DEFAULT})')
    parser.add_argument('--baud', type=int, default=BAUD_DEFAULT, help=f'UART baudrate (default: {BAUD_DEFAULT})')
    parser.add_argument('--size', type=int, nargs='+', required=True, help='Decrypt sizes in bytes; use 39552 for the full late-weight blob')
    parser.add_argument('--runs', type=int, default=10, help='Number of attempts per size (default: 10)')
    parser.add_argument('--output', type=str, default=None, help='Optional JSON output path')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.runs <= 0:
        raise ValueError('--runs must be > 0')

    output_path = Path(args.output) if args.output else Path(__file__).resolve().parents[1] / 'build' / 'create_enclave_size_benchmark.json'

    device = UartDevice(args.port, args.baud)
    results = []

    try:
        device.connect()
        for requested_size in args.size:
            if requested_size <= 0:
                raise ValueError('Decrypt size must be > 0; use 39552 for the full late-weight blob')

            samples = []
            for attempt in range(args.runs):
                secure_baseline = read_secure_benchmark(device)
                _, create_host_ms = send_create(device, requested_size)
                secure_after_create = read_secure_benchmark(device)
                _, destroy_host_ms = send_destroy(device)
                secure_after_destroy = read_secure_benchmark(device)

                secure_create_total = delta(secure_after_create, secure_baseline, 'create_enclave_cycles')
                secure_create_validate = delta(secure_after_create, secure_baseline, 'create_validate_cycles')
                secure_create_recompute = delta(secure_after_create, secure_baseline, 'create_recompute_cycles')
                secure_aes_decrypt = delta(secure_after_create, secure_baseline, 'aes_decrypt_cycles')
                secure_destroy_total = delta(secure_after_destroy, secure_after_create, 'destroy_enclave_cycles')
                secure_destroy_sau_open = delta(secure_after_destroy, secure_after_create, 'sau_sync_open_cycles')
                secure_destroy_sau_close = delta(secure_after_destroy, secure_after_create, 'sau_sync_close_cycles')

                samples.append({
                    'attempt': attempt + 1,
                    'host_create_ms': round(create_host_ms, 3),
                    'host_destroy_ms': round(destroy_host_ms, 3),
                    'secure_create_total': secure_create_total,
                    'secure_create_validate': secure_create_validate,
                    'secure_aes_decrypt': secure_aes_decrypt,
                    'secure_create_recompute': secure_create_recompute,
                    'secure_destroy_total': secure_destroy_total,
                    'secure_destroy_sau_open': secure_destroy_sau_open,
                    'secure_destroy_sau_close': secure_destroy_sau_close,
                    'secure_metrics': {
                        'secure_create_total': secure_create_total,
                        'secure_create_validate': secure_create_validate,
                        'secure_aes_decrypt': secure_aes_decrypt,
                        'secure_create_recompute': secure_create_recompute,
                        'secure_destroy_total': secure_destroy_total,
                        'secure_destroy_sau_open': secure_destroy_sau_open,
                        'secure_destroy_sau_close': secure_destroy_sau_close,
                    },
                })

            secure_metric_keys = [
                'secure_create_total',
                'secure_create_validate',
                'secure_aes_decrypt',
                'secure_create_recompute',
                'secure_destroy_total',
                'secure_destroy_sau_open',
                'secure_destroy_sau_close',
            ]
            secure_metrics_avg = {
                key: round(mean(sample['secure_metrics'][key] for sample in samples), 3)
                for key in secure_metric_keys
            }

            result = {
                'requested_decrypt_size_bytes': int(requested_size),
                'runs': int(args.runs),
                'samples': samples,
                'secure_metrics_avg': secure_metrics_avg,
                'host_create_ms_mean': round(mean(sample['host_create_ms'] for sample in samples), 3),
                'host_create_ms_stddev': round(stdev(sample['host_create_ms'] for sample in samples), 3) if len(samples) > 1 else 0.0,
                'host_destroy_ms_mean': round(mean(sample['host_destroy_ms'] for sample in samples), 3),
                'host_destroy_ms_stddev': round(stdev(sample['host_destroy_ms'] for sample in samples), 3) if len(samples) > 1 else 0.0,
            }
            results.append(result)

            print(
                f"size={requested_size}B runs={args.runs} "
                f"create_secure={result['secure_metrics_avg']['secure_create_total']:.1f} cycles "
                f"decrypt_secure={result['secure_metrics_avg']['secure_aes_decrypt']:.1f} cycles "
                f"destroy_secure={result['secure_metrics_avg']['secure_destroy_total']:.1f} cycles"
            )

            print_breakdown(result['requested_decrypt_size_bytes'], result['secure_metrics_avg'])

        payload = {
            'port': args.port,
            'baud': args.baud,
            'cpu_mhz': CPU_MHZ,
            'results': results,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
        print(f'[OK] Benchmark written: {output_path}')
        return 0
    finally:
        device.disconnect()


if __name__ == '__main__':
    sys.exit(main())
