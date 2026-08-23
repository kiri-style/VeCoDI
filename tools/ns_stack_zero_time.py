#!/usr/bin/env python3
"""Compute the time required to zero the NS stack using measured STM cycle counts.

This script can be used in two ways:
  1) with a known cycle value: --cycles 123456
  2) directly from the board: --port /dev/tty.usbmodem21103

Typical usage:
  python3 tools/ns_stack_zero_time.py --cycles 123456
  python3 tools/ns_stack_zero_time.py --json build/ns_stack_zero.json
  python3 tools/ns_stack_zero_time.py --port /dev/tty.usbmodem21103
  python3 tools/ns_stack_zero_time.py
"""

import argparse
import glob
import json
import serial
import struct
import sys
import time
from pathlib import Path

DEFAULT_CPU_HZ = 110_000_000
STACK_ZERO_CMD = 0x1C


def cycles_to_seconds(cycles: int, cpu_hz: int = DEFAULT_CPU_HZ) -> float:
    if cpu_hz <= 0:
        raise ValueError("CPU clock must be > 0")
    return cycles / cpu_hz


def cycles_to_ms(cycles: int, cpu_hz: int = DEFAULT_CPU_HZ) -> float:
    return cycles_to_seconds(cycles, cpu_hz) * 1000.0


def cycles_to_us(cycles: int, cpu_hz: int = DEFAULT_CPU_HZ) -> float:
    return cycles_to_seconds(cycles, cpu_hz) * 1_000_000.0


def load_cycles_from_json(path: str | None, key_names: tuple[str, ...]) -> int:
    if path is None:
        raise ValueError("A JSON file path is required when using --json")

    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)

    if isinstance(data, dict):
        for key in key_names:
            if key in data:
                value = data[key]
                if isinstance(value, (int, float)):
                    return int(value)
        raise KeyError(f"No supported key in JSON: {key_names}")

    raise TypeError("JSON root must be a dictionary")


def auto_detect_port() -> str | None:
    candidates = []
    candidates.extend(glob.glob('/dev/tty.usbmodem*'))
    candidates.extend(glob.glob('/dev/tty.usbserial*'))
    candidates.extend(glob.glob('/dev/cu.usbmodem*'))
    candidates.extend(glob.glob('/dev/cu.usbserial*'))
    for port in candidates:
        try:
            with serial.Serial(port, 115200, timeout=0.2):
                return port
        except Exception:
            continue
    return None


def read_cycles_from_board(port: str, baudrate: int = 115200, timeout: float = 10.0, command: int = STACK_ZERO_CMD) -> int:
    ser = serial.Serial(port=port, baudrate=baudrate, timeout=timeout)
    try:
        time.sleep(2.5)
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        packet = struct.pack('<BI', command, 0)
        ser.write(packet)
        ser.flush()

        status = ser.read(1)
        if len(status) != 1:
            raise TimeoutError(f"No status byte from {port}")
        if status[0] != 0x00:
            raise RuntimeError(f"Board returned status 0x{status[0]:02x} instead of RESP_OK")

        length_raw = ser.read(4)
        if len(length_raw) != 4:
            raise TimeoutError(f"No length field from {port}")
        length = struct.unpack('<I', length_raw)[0]
        if length != 4:
            raise ValueError(f"Unexpected payload length: {length} bytes (expected 4)")

        data = ser.read(length)
        if len(data) != length:
            raise TimeoutError(f"Short payload {len(data)}/{length} bytes from {port}")
        return struct.unpack('<I', data)[0]
    finally:
        ser.close()


def print_summary(cycles: int, cpu_hz: int, stack_bytes: int) -> None:
    seconds = cycles_to_seconds(cycles, cpu_hz)
    ms = cycles_to_ms(cycles, cpu_hz)
    us = cycles_to_us(cycles, cpu_hz)

    print("=== NS stack zero benchmark ===")
    print(f"CPU clock      : {cpu_hz:,} Hz")
    print(f"Stack size     : {stack_bytes:,} bytes")
    print(f"Cycle count    : {cycles:,} cycles")
    print(f"Time in us     : {us:,.3f} us")
    print(f"Time in ms     : {ms:,.3f} ms")
    print(f"Time in s      : {seconds:.6f} s")
    print(f"Cycles/byte    : {cycles / max(stack_bytes, 1):.3f} cycles/byte")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert STM cycle counts into NS stack zeroing time.",
    )
    parser.add_argument("--cycles", type=int, default=None, help="Measured cycle count from the STM32")
    parser.add_argument("--json", type=str, default=None, help="JSON file containing cycle count data")
    parser.add_argument(
        "--json-key",
        type=str,
        default="stack_zero_cycles",
        help="Key name inside JSON, default: stack_zero_cycles",
    )
    parser.add_argument("--port", type=str, default=None, help="Serial port on which the board is connected, e.g. /dev/tty.usbmodem21103")
    parser.add_argument("--baudrate", type=int, default=115200, help="UART baudrate for the board connection")
    parser.add_argument("--timeout", type=float, default=10.0, help="Serial read timeout in seconds")
    parser.add_argument("--cpu-hz", type=int, default=DEFAULT_CPU_HZ, help=f"CPU clock in Hz (default: {DEFAULT_CPU_HZ})")
    parser.add_argument("--stack-bytes", type=int, default=3072, help="NS stack size in bytes used for the estimate")
    args = parser.parse_args()

    if args.cycles is None:
        if args.json is not None:
            args.cycles = load_cycles_from_json(args.json, (args.json_key, "ns_stack_zero_cycles", "stack_zero_cycles"))
        else:
            port = args.port or auto_detect_port()
            if port is None:
                parser.error("Either --cycles, --json, or a valid --port/auto-detected board port must be provided")
            print(f"[INFO] Reading stack-zero cycle count from {port}")
            args.cycles = read_cycles_from_board(port, baudrate=args.baudrate, timeout=args.timeout, command=STACK_ZERO_CMD)

    cycles = int(args.cycles)
    print_summary(cycles, args.cpu_hz, args.stack_bytes)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover
        print(f"ERR: {exc}", file=sys.stderr)
        raise SystemExit(1)
