# 100-Inference REAL Hardware Benchmark

## Scope

This benchmark now runs on the physical board and no longer relies on simulated inference data.

Measured flow per run:
1. `M_update`
2. `create enclave`
3. `verified inference`
4. `destroy enclave`

Target platform:
- STM32L552 Cortex-M33 @ 110 MHz
- TF-M Secure World
- UART protocol via `/dev/cu.usbmodem1203` (macOS default)

## What Changed

Previous `100 inferences` workflow generated synthetic values with a Python generator. That path produced a ~25 ms figure for an atomic inference profile, but it was not acquired from board execution.

Current workflow is hardware-real:
- `tools/benchmark_100_inferences.py` calls `tools/full_flow_benchmark.py` directly on device.
- Optional board flash is integrated.
- Output JSON now contains real on-device cycle counters and host timing.

## Run Command (Real Device)

From project root:

```bash
python3 tools/benchmark_100_inferences.py \
  --flash \
  --boot-wait 20 \
  --port /dev/cu.usbmodem1203 \
  --runs 100 \
  --c-limit 11 \
  --image cifar_input.raw \
  --image-label 3 \
  --output build/full_flow_benchmark_100_real.json
```

## Output Files

Primary output:
- `build/full_flow_benchmark_100_real.json`

Schema highlights:
- `samples[].m_update_cycles`
- `samples[].create_enclave_cycles`
- `samples[].inference_cycles`
- `samples[].destroy_enclave_cycles`
- `summary.*`

## Cycles to Milliseconds

Use board frequency conversion:

- `ms = cycles / 110000`

Examples:
- `2,750,000 cycles -> 25.0 ms`
- `5,320,000 cycles -> 48.36 ms`

## Notes for Reproducibility

- Prefer `/dev/cu.usbmodem*` on macOS for outbound serial sessions.
- Keep a post-flash boot delay (`--boot-wait`) to avoid first-command UART timeouts.
- `c_limit` must be strictly greater than current device max; `full_flow_benchmark.py` auto-adjusts upward when needed.
- This benchmark is full secure flow, not atomic-inference-only. If you need strict atomic inference timing, use a dedicated atomic path.
