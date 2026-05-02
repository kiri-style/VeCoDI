#!/usr/bin/env python3
"""
Benchmark the full VECODI security flow:
M_update -> create enclave -> inference -> destroy enclave

This script reuses the UART protocol and case-study helpers already present in
the repository and records host-side duration plus device-side counters.
"""

import argparse
import json
import struct
import sys
import time
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Dict, List, Optional, Tuple

from vecodi_case_study import VecodiCaseStudy, UartDevice


PORT_DEFAULT = "/dev/cu.usbmodem1203"
BAUD_DEFAULT = 115200
CMD_GET_BENCHMARK = 0x08
CMD_GET_SECURE_BENCHMARK = 0x09
CMD_GET_M_UPDATE_DEBUG = 0x1A
CPU_MHZ = 110.0

DEVICE_BENCHMARK_NAMES = [
    "enclave_create_cycles", "enclave_destroy_cycles", "aes_decrypt_cycles",
    "early_layers_cycles", "late_layers_cycles", "total_inference_cycles", "run_enclave_cycles", "full_execute_cycles",
    "heap_used_bytes", "heap_free_bytes", "stack_used_bytes",
    "ram_used_bytes", "ram_total_bytes", "flash_used_bytes", "flash_total_bytes",
    "inference_count", "enclave_recreations", "inference_requests_total", "enclave_info_validation_failures",
    "enclave_create_sum_cycles", "enclave_destroy_sum_cycles", "aes_decrypt_sum_cycles",
    "early_layers_sum_cycles", "late_layers_sum_cycles", "total_inference_sum_cycles", "run_enclave_sum_cycles", "irq_atomic_sum_cycles",
    "enclave_create_min_cycles", "enclave_create_max_cycles", "enclave_destroy_min_cycles", "enclave_destroy_max_cycles",
    "aes_decrypt_min_cycles", "aes_decrypt_max_cycles", "early_layers_min_cycles", "early_layers_max_cycles",
    "late_layers_min_cycles", "late_layers_max_cycles", "total_inference_min_cycles", "total_inference_max_cycles",
    "run_enclave_min_cycles", "run_enclave_max_cycles", "irq_atomic_min_cycles", "irq_atomic_max_cycles",
    "enclave_create_count", "enclave_destroy_count", "aes_decrypt_count", "early_layers_count", "late_layers_count", "total_inference_count", "run_enclave_count", "irq_atomic_count",
    "full_execute_count", "full_execute_sum_cycles", "full_execute_min_cycles", "full_execute_max_cycles",
    "create_atomic_sum_cycles", "destroy_atomic_sum_cycles",
    "create_atomic_min_cycles", "create_atomic_max_cycles", "destroy_atomic_min_cycles", "destroy_atomic_max_cycles", "create_atomic_count", "destroy_atomic_count",
    "run_inference_with_image_count", "dangerous_inference_no_sau_count", "dangerous_read_ram_count", "dangerous_read_rom_count",
    "m_update_cycles", "m_update_count",
]
DEVICE_BENCHMARK_FMT = "<" + "I" * 19 + "xxxx" + "Q" * 8 + "I" * 16 + "I" * 8 + "I" + "xxxx" + "Q" + "I" * 2 + "Q" * 2 + "I" * 6 + "I" * 4 + "xxxxQI"

SECURE_BENCHMARK_NAMES = [
    "aes_decrypt_cycles", "late_hash_cycles", "digest_compute_cycles", "m_update_cycles",
    "get_max_cycles", "check_allowed_cycles", "increment_cycles", "reset_cycles",
    "create_enclave_cycles", "finalize_create_cycles", "destroy_enclave_cycles",
    "inf_start_cycles", "inf_complete_cycles",
    "sau_sync_open_cycles", "sau_sync_close_cycles", "sau_flash_close_cycles",
    "sau_flash_open_cycles", "sau_flash_pulse_cycles",
    "aes_decrypt_count", "late_hash_count", "digest_count", "m_update_count",
    "counter_operations", "create_enclave_count", "finalize_create_count",
    "destroy_enclave_count", "inf_start_count", "inf_complete_count",
    "sau_sync_open_count", "sau_sync_close_count", "sau_flash_close_count",
    "sau_flash_open_count", "sau_flash_pulse_count",
    "ram_used_bytes", "ram_total_bytes", "flash_used_bytes", "flash_total_bytes",
]
SECURE_BENCHMARK_FMT = "<" + ("Q" * 18) + ("I" * 19)


def read_device_benchmark(device: UartDevice) -> Dict[str, int]:
    attempts = 3
    expected = struct.calcsize(DEVICE_BENCHMARK_FMT)
    last_error = None

    for _ in range(attempts):
        try:
            device.send_command(CMD_GET_BENCHMARK)
            status, payload = device.read_response(timeout=6.0)
            if status != 0:
                last_error = RuntimeError(f'CMD_GET_BENCHMARK failed with status {status}')
                time.sleep(0.05)
                continue
            if len(payload) < expected:
                raise RuntimeError(f'Benchmark payload too short: got {len(payload)}, expected {expected}')
            values = struct.unpack(DEVICE_BENCHMARK_FMT, payload[:expected])
            return {name: int(value) for name, value in zip(DEVICE_BENCHMARK_NAMES, values)}
        except Exception as exc:
            last_error = exc
            time.sleep(0.05)

    raise RuntimeError(f'Failed to read device benchmark after retries: {last_error}')


def read_ns_m_update(device: UartDevice) -> tuple[int, int]:
    """Read NS-side m_update cumulative counters via debug command.

    Returns (cycles, count)
    """
    device.send_command(CMD_GET_M_UPDATE_DEBUG)
    status, payload = device.read_response(timeout=2.0)
    if status != 0:
        raise RuntimeError(f'CMD_GET_M_UPDATE_DEBUG failed with status {status}')
    if len(payload) < 12:
        raise RuntimeError(f'm_update debug payload too short: {len(payload)}')
    cycles = int.from_bytes(payload[0:8], 'little')
    count = int.from_bytes(payload[8:12], 'little')
    return cycles, count


def read_secure_benchmark(device: UartDevice) -> Dict[str, int]:
    device.send_command(CMD_GET_SECURE_BENCHMARK)
    status, payload = device.read_response(timeout=8.0)
    if status != 0:
        raise RuntimeError(f"CMD_GET_SECURE_BENCHMARK failed with status {status}")

    expected = struct.calcsize(SECURE_BENCHMARK_FMT)
    if len(payload) < expected:
        raise RuntimeError(f"Secure benchmark payload too short: got {len(payload)}, expected {expected}")

    values = struct.unpack(SECURE_BENCHMARK_FMT, payload[:expected])
    return {name: int(value) for name, value in zip(SECURE_BENCHMARK_NAMES, values)}


def timed_call(fn, *args, **kwargs) -> Tuple[Any, float]:
    started = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return result, elapsed_ms


def cycles_to_ms(cycles: int) -> float:
    return cycles / (CPU_MHZ * 1000.0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark M_update, create, inference, and destroy")
    parser.add_argument("port", nargs="?", default=PORT_DEFAULT, help=f"Serial device (default: {PORT_DEFAULT})")
    parser.add_argument("--baud", type=int, default=BAUD_DEFAULT, help=f"UART baudrate (default: {BAUD_DEFAULT})")
    parser.add_argument("--runs", type=int, default=10, help="Number of full flow runs (default: 10)")
    parser.add_argument("--c-limit", type=int, default=10, help="Starting quota for M_update (each run increments by 1)")
    parser.add_argument("--model-id", type=lambda v: int(v, 0), default=0x00000001, help="Model ID (supports hex)")
    parser.add_argument("--image", type=str, default=None, help="Optional image from Mac to send to board (raw 3072B or PNG/JPEG)")
    parser.add_argument("--image-label", type=int, default=0, help="Expected label byte used with --image (default: 0)")
    parser.add_argument("--use-device-image", action="store_true", help="Use a test image from device memory instead of uploading from Mac")
    parser.add_argument("--output", type=str, default=None, help="Optional JSON output path")
    return parser.parse_args()


def summarize(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"min": 0.0, "max": 0.0, "avg": 0.0, "stddev": 0.0}
    return {
        "min": round(min(values), 3),
        "max": round(max(values), 3),
        "avg": round(mean(values), 3),
        "stddev": round(stdev(values), 3) if len(values) > 1 else 0.0,
    }


def delta(after: Dict[str, int], before: Dict[str, int], key: str) -> int:
    return int(after[key]) - int(before[key])


def per_op_cycles(
    after: Dict[str, int],
    before: Dict[str, int],
    sum_key: str,
    count_key: str,
    fallback_key: str,
) -> int:
    count_delta = delta(after, before, count_key)
    if count_delta > 0:
        sum_delta = delta(after, before, sum_key)
        return int(round(sum_delta / count_delta))
    # If no operations were counted on device side, avoid returning a
    # spurious fallback delta (which can be huge due to packing/endianness
    # issues). Return 0 to indicate 'not available'.
    return 0


def maybe_per_op_cycles(
    after: Dict[str, int],
    before: Dict[str, int],
    sum_key: str,
    count_key: str,
    fallback_key: str,
) -> Optional[int]:
    if sum_key not in after or sum_key not in before:
        return None
    return per_op_cycles(after, before, sum_key, count_key, fallback_key)


def main() -> int:
    args = parse_args()
    if args.runs <= 0:
        raise ValueError("--runs must be > 0")
    if args.c_limit <= 0:
        raise ValueError("--c-limit must be > 0")
    if args.image_label < 0 or args.image_label > 255:
        raise ValueError("--image-label must be in [0,255]")

    project_dir = Path(__file__).resolve().parents[1]
    output_path = Path(args.output) if args.output else project_dir / "build" / "full_flow_benchmark.json"

    image_payload: Optional[bytes] = None
    if args.image and not args.use_device_image:
        from vecodi_case_study import load_image_from_mac

        image_payload = load_image_from_mac(args.image)

    print(
        """
╔════════════════════════════════════════════════════════════════════╗
║     VECODI Full Flow Benchmark                                     ║
║   M_update -> create -> inference -> destroy                       ║
╚════════════════════════════════════════════════════════════════════╝
        """
    )
    print(f"Project: {project_dir}")
    print(f"Runs: {args.runs}")
    if image_payload is not None:
        print(f"Image upload: enabled ({len(image_payload)} bytes from Mac)")
    elif args.use_device_image:
        print("Image source: device test_images (internal sample on board)")

    device = UartDevice(args.port, args.baud)
    case_study = VecodiCaseStudy(device=device, model_id=args.model_id)
    samples: List[Dict[str, Any]] = []

    try:
        device.connect()

        print("Step 0: Provider setup (ECDH + EnclaveInfo)")
        timed_call(case_study.provider_ecdh_handshake)
        timed_call(case_study.provider_fetch_enclave_info)

        current_max = case_study.get_max_inferences()
        start_c_limit = max(args.c_limit, current_max + 1)
        if start_c_limit != args.c_limit:
            print(f"Adjusted starting c_limit from {args.c_limit} to {start_c_limit} to satisfy device policy")

        for run in range(args.runs):
            c_limit = start_c_limit + run
            print(f"\nRun {run + 1}/{args.runs} (c_limit={c_limit})")

            before_device = read_device_benchmark(device)
            before_ns_cycles, before_ns_count = read_ns_m_update(device)
            before_secure = read_secure_benchmark(device)

            _, m_update_ms = timed_call(case_study.provider_send_m_update, c_limit)
            after_m_update_secure = read_secure_benchmark(device)
            after_m_update_device = read_device_benchmark(device)
            after_ns_cycles, after_ns_count = read_ns_m_update(device)

            _, create_ms = timed_call(case_study.customer_create_enclave)
            after_create_device = read_device_benchmark(device)
            after_create_secure = read_secure_benchmark(device)

            before_inference_device = dict(after_create_device)
            before_inference_secure = dict(after_create_secure)
            _, inference_ms = timed_call(
                case_study.customer_verified_inference,
                image_payload,
                args.image_label,
            )
            after_inference_device = read_device_benchmark(device)
            after_inference_secure = read_secure_benchmark(device)

            before_destroy_device = dict(after_inference_device)
            before_destroy_secure = dict(after_inference_secure)
            _, destroy_ms = timed_call(case_study.customer_destroy_enclave)
            after_destroy_device = read_device_benchmark(device)
            after_destroy_secure = read_secure_benchmark(device)

            sample = {
                "attempt": run + 1,
                "c_limit": c_limit,
                "host_m_update_ms": round(m_update_ms, 3),
                "host_create_ms": round(create_ms, 3),
                "host_inference_ms": round(inference_ms, 3),
                "host_destroy_ms": round(destroy_ms, 3),
                "m_update_cycles": per_op_cycles(
                    after_m_update_secure,
                    before_secure,
                    "m_update_cycles",
                    "m_update_count",
                    "m_update_cycles",
                ),
                "m_update_count": delta(after_m_update_secure, before_secure, "m_update_count"),
                # Use explicit NS debug command for reliable NS-side m_update counters
                "ns_m_update_cycles": int((after_ns_cycles - before_ns_cycles) // (after_ns_count - before_ns_count)) if (after_ns_count - before_ns_count) > 0 else 0,
                "ns_m_update_count": int(after_ns_count - before_ns_count),
                "create_enclave_cycles": per_op_cycles(
                    after_create_device,
                    before_device,
                    "enclave_create_sum_cycles",
                    "enclave_create_count",
                    "enclave_create_cycles",
                ),
                "create_enclave_count": delta(after_create_device, before_device, "enclave_create_count"),
                "secure_create_enclave_cycles": per_op_cycles(
                    after_create_secure,
                    after_m_update_secure,
                    "create_enclave_cycles",
                    "create_enclave_count",
                    "create_enclave_cycles",
                ),
                "secure_create_enclave_count": delta(after_create_secure, after_m_update_secure, "create_enclave_count"),
                "inference_cycles": per_op_cycles(
                    after_inference_device,
                    before_inference_device,
                    "total_inference_sum_cycles",
                    "total_inference_count",
                    "total_inference_cycles",
                ),
                "early_layers_cycles": per_op_cycles(
                    after_inference_device,
                    before_inference_device,
                    "early_layers_sum_cycles",
                    "early_layers_count",
                    "early_layers_cycles",
                ),
                "late_layers_cycles": per_op_cycles(
                    after_inference_device,
                    before_inference_device,
                    "late_layers_sum_cycles",
                    "late_layers_count",
                    "late_layers_cycles",
                ),
                "inference_count": delta(after_inference_device, before_inference_device, "inference_count"),
                "destroy_enclave_cycles": per_op_cycles(
                    after_destroy_device,
                    before_destroy_device,
                    "enclave_destroy_sum_cycles",
                    "enclave_destroy_count",
                    "enclave_destroy_cycles",
                ),
                "destroy_enclave_count": delta(after_destroy_device, before_destroy_device, "enclave_destroy_count"),
                "secure_destroy_enclave_cycles": per_op_cycles(
                    after_destroy_secure,
                    before_destroy_secure,
                    "destroy_enclave_cycles",
                    "destroy_enclave_count",
                    "destroy_enclave_cycles",
                ),
                "secure_destroy_enclave_count": delta(after_destroy_secure, before_destroy_secure, "destroy_enclave_count"),
                "full_execute_cycles": per_op_cycles(
                    after_inference_device,
                    before_inference_device,
                    "full_execute_sum_cycles",
                    "full_execute_count",
                    "full_execute_cycles",
                ),
                "full_execute_count": delta(after_inference_device, before_inference_device, "full_execute_count"),
                "pox_cycles": maybe_per_op_cycles(
                    after_inference_secure,
                    before_inference_secure,
                    "inf_complete_cycles",
                    "inf_complete_count",
                    "inf_complete_cycles",
                ),
                "pox_count": delta(after_inference_secure, before_inference_secure, "inf_complete_count"),
                "baseline_create_count": int(before_device["enclave_create_count"]),
                "baseline_destroy_count": int(before_device["enclave_destroy_count"]),
                "baseline_m_update_count": int(before_secure["m_update_count"]),
                "baseline_inference_count": int(before_inference_device["inference_count"]),
            }
            samples.append(sample)

            print(
                f"  create={create_ms:6.2f}ms ({sample['create_enclave_cycles']:,} cycles), "
                f"inference={inference_ms:6.2f}ms ({sample['inference_cycles']:,} cycles), "
                f"m_update={m_update_ms:6.2f}ms ({sample['m_update_cycles']:,} cycles), "
                f"destroy={destroy_ms:6.2f}ms ({sample['destroy_enclave_cycles']:,} cycles)"
            )

        summary = {
            "host_m_update_ms": summarize([sample["host_m_update_ms"] for sample in samples]),
            "host_create_ms": summarize([sample["host_create_ms"] for sample in samples]),
            "host_inference_ms": summarize([sample["host_inference_ms"] for sample in samples]),
            "host_destroy_ms": summarize([sample["host_destroy_ms"] for sample in samples]),
            "m_update_cycles": summarize([float(sample["m_update_cycles"]) for sample in samples]),
            "ns_m_update_cycles": summarize([float(sample["ns_m_update_cycles"]) for sample in samples]),
            "create_enclave_cycles": summarize([float(sample["create_enclave_cycles"]) for sample in samples]),
            "secure_create_enclave_cycles": summarize([float(sample["secure_create_enclave_cycles"]) for sample in samples]),
            "inference_cycles": summarize([float(sample["inference_cycles"]) for sample in samples]),
            "full_execute_cycles": summarize([float(sample["full_execute_cycles"]) for sample in samples]),
            "pox_cycles": summarize([float(sample["pox_cycles"]) for sample in samples if sample["pox_cycles"] is not None]),
            "destroy_enclave_cycles": summarize([float(sample["destroy_enclave_cycles"]) for sample in samples]),
            "secure_destroy_enclave_cycles": summarize([float(sample["secure_destroy_enclave_cycles"]) for sample in samples]),
        }

        payload = {
            "port": args.port,
            "baud": args.baud,
            "runs": int(args.runs),
            "model_id": int(args.model_id),
            "c_limit_start": int(start_c_limit),
            "image_used": bool(image_payload is not None),
            "image_source": "mac" if image_payload is not None else "device",
            "samples": samples,
            "summary": summary,
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        print("\n=== FULL FLOW SUMMARY ===")
        print(
            f"M_update: {summary['host_m_update_ms']['avg']:.3f} ± {summary['host_m_update_ms']['stddev']:.3f} ms (host) "
            f"({int(summary['m_update_cycles']['avg']):,} cycles avg secure | {int(summary['ns_m_update_cycles']['avg']):,} cycles avg ns)"
        )
        print(
            f"CREATE:   {summary['host_create_ms']['avg']:.3f} ± {summary['host_create_ms']['stddev']:.3f} ms (host) "
            f"({int(summary['create_enclave_cycles']['avg']):,} cycles avg ns | {int(summary['secure_create_enclave_cycles']['avg']):,} cycles avg secure)"
        )
        print(
            f"INFER:    {summary['host_inference_ms']['avg']:.3f} ± {summary['host_inference_ms']['stddev']:.3f} ms (host) "
            f"({int(summary['inference_cycles']['avg']):,} cycles avg)"
        )
        print(
            f"FULL EXEC:{summary['host_inference_ms']['avg']:.3f} ms host | "
            f"{int(summary['full_execute_cycles']['avg']):,} cycles avg on device"
        )
        if summary.get("pox_cycles", {}).get("count", 0) > 0:
            print(
                f"POX:      {int(summary['pox_cycles']['avg']):,} cycles avg on device "
                f"({cycles_to_ms(int(summary['pox_cycles']['avg'])):.3f} ms)"
            )
        print(
            f"DESTROY:  {summary['host_destroy_ms']['avg']:.3f} ± {summary['host_destroy_ms']['stddev']:.3f} ms (host) "
            f"({int(summary['destroy_enclave_cycles']['avg']):,} cycles avg ns | {int(summary['secure_destroy_enclave_cycles']['avg']):,} cycles avg secure)"
        )
        print(f"[OK] Benchmark written: {output_path}")
        return 0

    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    finally:
        device.disconnect()


if __name__ == "__main__":
    sys.exit(main())