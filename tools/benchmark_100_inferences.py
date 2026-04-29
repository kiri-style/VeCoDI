#!/usr/bin/env python3
"""Run 100 real hardware inferences via full_flow_benchmark.py.

This replaces the old simulated generator path and executes on-device runs.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run real 100-inference benchmark on hardware")
    parser.add_argument("--port", default="/dev/cu.usbmodem1203", help="Serial port")
    parser.add_argument("--baud", type=int, default=115200, help="UART baudrate")
    parser.add_argument("--runs", type=int, default=100, help="Number of real runs")
    parser.add_argument("--c-limit", type=int, default=11, help="Initial c_limit (auto-adjusted by full_flow_benchmark)")
    parser.add_argument("--image", default="cifar_input.raw", help="Image payload path")
    parser.add_argument("--image-label", type=int, default=3, help="Image label byte")
    parser.add_argument("--flash", action="store_true", help="Flash board before benchmark")
    parser.add_argument("--boot-wait", type=int, default=20, help="Seconds to wait after flash")
    parser.add_argument("--output", default="build/full_flow_benchmark_100_real.json", help="Output JSON path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_dir = Path(__file__).parent.parent.absolute()

    print("""
╔════════════════════════════════════════════════════════════════════╗
║        100-Inference REAL Hardware Benchmark                      ║
║    (M_update + create + verified inference + destroy)             ║
╚════════════════════════════════════════════════════════════════════╝
    """)
    print(f"Project: {project_dir}")
    print(f"Runs: {args.runs}")
    print(f"Port: {args.port}")

    if args.flash:
        print("\nStep 1: Flashing board...")
        result = subprocess.run(["west", "flash"], cwd=project_dir)
        if result.returncode != 0:
            print("❌ Flash failed")
            return result.returncode

        if args.boot_wait > 0:
            print(f"Step 2: Waiting {args.boot_wait}s for board boot...")
            subprocess.run(["sleep", str(args.boot_wait)], cwd=project_dir)

    print("\nStep 3: Running real benchmark on device...\n")
    cmd = [
        sys.executable,
        str(project_dir / "tools" / "full_flow_benchmark.py"),
        args.port,
        "--baud", str(args.baud),
        "--runs", str(args.runs),
        "--c-limit", str(args.c_limit),
        "--image", args.image,
        "--image-label", str(args.image_label),
        "--output", args.output,
    ]

    result = subprocess.run(cmd, cwd=project_dir)
    if result.returncode != 0:
        print("❌ Benchmark failed")
        return result.returncode

    print(f"\n✅ Real benchmark complete: {project_dir / args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
